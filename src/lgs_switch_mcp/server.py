"""stdio MCP server entrypoint. Connections are opened only when a tool runs."""

from __future__ import annotations

import atexit
import functools
import inspect
import json
import os
import re
import signal
import sys
from contextvars import ContextVar
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from mcp.server import MCPServer
from netmiko_mcp.security import validate_command

from lgs_switch_mcp import (
    configdump,
    configstore,
    connection,
    readtools,
    writes,
    writetools,
)
from lgs_switch_mcp.audit import audited_call, check_audit_path
from lgs_switch_mcp.connection import (
    CONFIG_ERROR_PATTERN,
    READBACK_DESCRIPTION,
    SwitchConnectionError,
    _send_config,
    build_description_commands,
    call_budget,
    call_deadline,
    read_timeout,
    redact_show_output,
    run_in_session,
    run_show,
    run_show_sequence,
    save_in_session,
    send_paged,
    send_paged_redacted,
    session_log_path,
)
from lgs_switch_mcp.snmp_cli import (
    CLI_SOURCE,
    POE_SUBTREE,
    READBACK_SNMP_ACCESS,
    READBACK_SNMP_COMMUNITY,
    READBACK_SNMP_GROUP,
    READBACK_SNMP_USER,
    READBACK_SNMP_VIEW,
    WRITE_ALLOWED_SUBTREES,
    ViewSubtree,
    assert_configured_community_ready,
    build_community_create_commands,
    build_community_remove_commands,
    build_user_remove_commands,
    build_view_create_commands,
    build_write_view_commands,
    canonical_oid,
    case_variant_note,
    case_variant_view_names,
    format_sent_commands,
    normalize_subtree,
    normalize_write_subtree,
    oid_within,
    parse_snmp_access,
    parse_snmp_community,
    parse_snmp_viewtree,
    redact_command_list,
    resolve_removable_community_name,
    user_present,
    view_entry_problem,
    view_entry_set,
    view_included_oids,
    view_is_restricted,
    view_is_write_safe,
)
from lgs_switch_mcp.tables import parse_system_information
from lgs_switch_mcp.toolkit import (
    fail,
    ok,
    prepare_runtime,
    with_audit_warning,
)
from lgs_switch_mcp.validation import (
    ValidationError,
    canonical_port,
    port_policy_text,
    redact_secrets,
    reject_protected_port,
    reject_unsafe_show_command,
    require_caution_confirmation,
    require_snmp_write_enabled,
    validate_community_remove_name,
    validate_description,
    validate_port,
    validate_snmp_access,
    validate_snmp_community_secret,
    validate_snmp_name,
    validate_user_remove_name,
)

try:
    _PKG_VERSION = version("lgs-switch-mcp")
except PackageNotFoundError:  # pragma: no cover
    from lgs_switch_mcp import __version__ as _PKG_VERSION

mcp = MCPServer(
    name="lgs-switch-mcp",
    instructions=(
        "MCP server for a single Linksys LGS-series switch, based on "
        "netmiko and netmiko-mcp. Use show for allow-listed read commands "
        "and the parsed read tools (health_summary, port_status, "
        "port_counters, counters_delta, mac_table, lldp_neighbors, "
        "poe_status, config_read, config_backup, config_diff, audit_tail, "
        "show_help) for JSON. Configuration tools build fixed CLI "
        "sequences; they do not accept free-form config. Every write tool "
        "defaults to dry_run=true and only shows the commands, the current "
        "and the expected state; pass dry_run=false to apply. Real writes "
        "store a masked config snapshot first and return a before/after "
        "diff. Protected ports are refused, caution ports need "
        "confirm_caution_port=true. There are no VLAN, reboot, or reset "
        "tools. SNMP write tools are narrow and gated by hub unlock, like "
        "save_config. Secrets are redacted as [REDACTED] or "
        "[REDACTED-LINE]. Changes are not saved until save_config is "
        "called with dry_run=false. The startup-config cannot be read on "
        "this device. "
    ) + port_policy_text(),
    version=_PKG_VERSION,
)

PORT_OVERVIEW_COMMANDS = (
    "show system information",
    "show vlan",
    "show power inline",
    "show interfaces",
)


_with_audit_warning = with_audit_warning
_fail = fail
_ok = ok


def startup_checks() -> list[str]:
    """Check local paths and settings at start. Warn on stderr, never abort,
    never contact the switch."""
    warnings: list[str] = []
    audit_warning = check_audit_path()
    if audit_warning:
        warnings.append(audit_warning)
    try:
        read_timeout()
    except ValidationError as exc:
        warnings.append(str(exc))
        print(f"lgs-switch-mcp: warning: {exc}", file=sys.stderr, flush=True)
    session_log_path()
    if "SWITCH_SNMP_COMMUNITY" in os.environ:
        try:
            validate_snmp_community_secret()
        except ValidationError as exc:
            # Invalid values are not used for redaction; never echo them.
            warnings.append(str(exc))
            print(
                f"lgs-switch-mcp: warning: {exc}",
                file=sys.stderr,
                flush=True,
            )
    write_flag = (os.environ.get("SWITCH_SNMP_WRITE_ENABLED") or "").strip()
    if write_flag != "1":
        message = (
            "SNMP write tools are disabled (SWITCH_SNMP_WRITE_ENABLED "
            "is not 1) until the CLI syntax is live-confirmed."
        )
        warnings.append(message)
        print(f"lgs-switch-mcp: warning: {message}", file=sys.stderr, flush=True)
    return warnings


def show(command: str) -> str:
    """Run an allow-listed show command on the switch (no TextFSM parsing)."""
    params = {"command": command}
    command_file = (os.environ.get("NETMIKO_MCP_COMMAND_FILE") or "").strip()
    if not command_file or not Path(command_file).expanduser().is_file():
        return _fail(
            "show",
            params,
            "Error: NETMIKO_MCP_COMMAND_FILE is not set or the file does not exist.",
            allowed=False,
        )
    prepare_runtime()
    try:
        reject_unsafe_show_command(command)
    except ValidationError as exc:
        return _fail("show", params, str(exc), allowed=False)
    verdict = validate_command(command)
    if not verdict.allowed:
        return _fail(
            "show",
            params,
            f"Command rejected: {verdict.reason}",
            allowed=False,
        )
    try:
        output = run_show(verdict.normalized_command)
    except (ValidationError, SwitchConnectionError) as exc:
        return _fail("show", params, f"Error: {exc}", allowed=True)
    return _ok("show", params, output)


def port_overview() -> str:
    """Read a bundle of allow-listed status commands in a single session.

    Read-only: runs only the hardcoded show commands through the same
    netmiko-mcp command filter as the show tool. Never sends config.
    """
    params: dict[str, Any] = {}
    command_file = (os.environ.get("NETMIKO_MCP_COMMAND_FILE") or "").strip()
    if not command_file or not Path(command_file).expanduser().is_file():
        return _fail(
            "port_overview",
            params,
            "Error: NETMIKO_MCP_COMMAND_FILE is not set or the file does not exist.",
            allowed=False,
        )
    prepare_runtime()
    sections: list[str] = []
    errors: list[str] = []
    allowed: list[tuple[str, str]] = []
    for command in PORT_OVERVIEW_COMMANDS:
        verdict = validate_command(command)
        if not verdict.allowed:
            errors.append(f"{command}: Command rejected: {verdict.reason}")
            continue
        allowed.append((command, verdict.normalized_command))
    if allowed:
        try:
            results = run_show_sequence([normalized for _, normalized in allowed])
        except (ValidationError, SwitchConnectionError) as exc:
            message = redact_secrets(str(exc))
            results = [(normalized, None, message) for _, normalized in allowed]
        for (command, _), (_, output, error) in zip(allowed, results, strict=True):
            if error is not None:
                errors.append(f"{command}: {redact_secrets(error)}")
            else:
                sections.append(f"=== {command} ===\n{output}")
    if errors and not sections:
        return _fail(
            "port_overview",
            params,
            "Error: " + " | ".join(errors),
            allowed=True,
        )
    body = "\n\n".join(sections)
    if errors:
        body += "\n\n=== errors ===\n" + "\n".join(errors)
    return _ok("port_overview", params, body)


def _collapse_ws(text: str) -> str:
    return " ".join(text.split())


_MIN_TRUNCATION_PREFIX = 8
_PREVIEW_LINES = 4

# Port 0/7 also appears as gi7, gi1/0/7, Gi0/7, or GigabitEthernet0/7.
# Longer patterns come first; a following alnum char rejects gi0/1 vs gi0/10.
_PORT_TOKEN_PATTERNS = (
    r"gigabitethernet\s*{port}",
    r"gigabitethernet\s*\d+/\d+/{number}",
    r"gigabitethernet\s*{number}",
    r"gi\s*{port}",
    r"gi\s*\d+/\d+/{number}",
    r"gi\s*{number}",
)


def _port_token_end(line: str, port: str) -> int | None:
    """If line starts with a recognised name for port, return the end index."""
    stripped = line.lstrip()
    pad = len(line) - len(stripped)
    lower = stripped.lower()
    number = port.split("/")[-1]
    values = {"port": re.escape(port), "number": re.escape(number)}
    for pattern in _PORT_TOKEN_PATTERNS:
        match = re.match(pattern.format(**values), lower)
        if match is None:
            continue
        end = match.end()
        # Reject a following alnum (gi0/1 vs gi0/10) or '/' (gi1 vs gi1/0/7).
        if end == len(stripped) or not (
            stripped[end].isalnum() or stripped[end] == "/"
        ):
            return pad + end
    return None


def _is_interface_row(line: str) -> bool:
    return bool(
        re.match(
            r"(?i)^\s*(?:gi|gigabitethernet)\s*\d+(?:/\d+){0,2}(?:\s|$|[^0-9a-z])",
            line,
        )
    )


def _ends_with_text(row: str, text: str) -> bool:
    haystack = _collapse_ws(row)
    needle = _collapse_ws(text)
    if not needle:
        return False
    return haystack == needle or haystack.endswith(" " + needle)


def _is_truncated(
    parsed: str, expected: str, *, column_width: int | None
) -> bool:
    parsed_n = _collapse_ws(parsed)
    expected_n = _collapse_ws(expected)
    if not parsed_n or parsed_n == expected_n or not expected_n.startswith(parsed_n):
        return False
    if len(parsed_n) >= _MIN_TRUNCATION_PREFIX:
        return True
    return column_width is not None and len(parsed) == column_width


def _is_separator(line: str) -> bool:
    stripped = line.strip()
    return bool(stripped) and bool(re.fullmatch(r"[\s\-=]+", line)) and any(
        char in stripped for char in "-="
    )


def _column_width_from_header(header: str, label_start: int, label_end: int) -> int | None:
    next_token = re.search(r"\S", header[label_end:])
    if next_token is None:
        return None
    width = (label_end + next_token.start()) - label_start
    return width if width > 0 else None


def _column_width_from_separator(line: str, header_col: int) -> int | None:
    # A distinct dash/equals bar starting at the header column, not a
    # single rule drawn across the whole table.
    if header_col >= len(line) or line[header_col] not in "-=":
        return None
    if header_col > 0 and line[header_col - 1] in "-=":
        return None
    end = header_col
    while end < len(line) and line[end] in "-=":
        end += 1
    width = end - header_col
    return width if width > 0 else None


def _output_preview(body: str) -> str:
    lines = [line.rstrip() for line in body.splitlines() if line.strip()]
    return "\n".join(lines[:_PREVIEW_LINES]) or "(empty)"


@dataclass(frozen=True)
class DescriptionRow:
    raw: str
    header_col: int | None
    parsed: str | None
    column_width: int | None


def find_description_row(
    output: str, port: str
) -> tuple[DescriptionRow | None, str]:
    """Locate the port row in a show interfaces description table.

    The second item is a short preview of the table body, for notes when
    the row cannot be found.
    """
    # run_config_and_readback wraps the table in a "--- <command> ---" line.
    # Do not treat a separator bar that merely contains " ---" as that wrapper.
    match = re.search(r"^--- .+ ---\n", output, re.MULTILINE)
    body = output[match.end() :] if match else output
    preview = _output_preview(body)
    header_col: int | None = None
    column_width: int | None = None
    for line in body.splitlines():
        raw = line.rstrip("\r")
        if not raw.strip():
            continue
        if not _is_interface_row(raw):
            if header_col is None:
                match = re.search(r"\bDescription\b", raw, re.IGNORECASE) or re.search(
                    r"\bName\b", raw, re.IGNORECASE
                )
                if match:
                    header_col = match.start()
                    column_width = _column_width_from_header(
                        raw, match.start(), match.end()
                    )
                    continue
            elif _is_separator(raw):
                sep_width = _column_width_from_separator(raw, header_col)
                if sep_width is not None:
                    column_width = sep_width
                continue
        if _port_token_end(raw, port) is None:
            continue
        if header_col is not None:
            field = raw[header_col:] if len(raw) > header_col else ""
            return (
                DescriptionRow(
                    raw=raw.rstrip(),
                    header_col=header_col,
                    parsed=field.strip(),
                    column_width=column_width,
                ),
                preview,
            )
        return (
            DescriptionRow(
                raw=raw.rstrip(),
                header_col=None,
                parsed=None,
                column_width=None,
            ),
            preview,
        )
    return None, preview


def parse_interface_description(output: str, port: str) -> str | None:
    """Return the header-column description for port, or None.

    ``None`` means the row was not found or the table header was not
    recognised (no Description/Name column). An empty string means the
    row was present with no description.
    """
    row, _ = find_description_row(output, port)
    if row is None or row.header_col is None:
        return None
    return row.parsed


def description_readback_note(readback: str, port: str, text: str | None) -> str:
    """Compare the parsed description for port with the requested text.

    The command is sent quoted; the switch should store and show the text
    without quotes. A quoted match means the quotes were stored literally.
    Comparisons collapse whitespace. Without a recognised header, a row
    that ends with the expected text is treated as verified; otherwise
    the note says the layout could not be verified. Truncation is
    accepted only for a strict prefix of at least 8 characters, or when
    a known column width (next header column or separator dash length)
    equals the parsed length. A missing row is never reported as a
    mismatch.
    """
    row, preview = find_description_row(readback, port)
    if row is None:
        return (
            "Read-back check: could not verify (port row not found). "
            f"Output starts with:\n{preview}"
        )
    if text is None:
        if row.header_col is None:
            end = _port_token_end(row.raw, port)
            remainder = _collapse_ws(row.raw[end:] if end is not None else row.raw)
            if not remainder:
                return "Read-back check: description is empty."
            return (
                "Read-back check: could not verify (unknown table layout): "
                f"{row.raw!r}"
            )
        if not row.parsed:
            return "Read-back check: description is empty."
        return f"Read-back check: description is still {row.parsed!r}."

    if row.header_col is None:
        if _ends_with_text(row.raw, f'"{text}"'):
            return (
                "Read-back check: description appears WITH quotes; the switch "
                "stored the quotes literally."
            )
        if _ends_with_text(row.raw, text):
            return "Read-back check: description found in read-back (without quotes)."
        return (
            "Read-back check: could not verify (unknown table layout): "
            f"{row.raw!r}"
        )

    parsed = row.parsed or ""
    parsed_n = _collapse_ws(parsed)
    if parsed_n == _collapse_ws(f'"{text}"'):
        return (
            "Read-back check: description appears WITH quotes; the switch "
            "stored the quotes literally."
        )
    if parsed_n == _collapse_ws(text):
        return "Read-back check: description found in read-back (without quotes)."
    if _is_truncated(parsed, text, column_width=row.column_width):
        return (
            "Read-back check: probably truncated by the switch table, ok "
            f"({parsed!r})."
        )
    if not parsed_n:
        return "Read-back check: description is empty in the read-back output."
    return f"Read-back check: description is {parsed!r}, expected {text!r}."


def port_set_description(
    port: str, text: str | None = None, confirm_caution_port: bool = False, dry_run: bool = True
) -> str:
    """Set an interface description, or clear it when text is omitted.

    Refused on protected ports (SWITCH_PROTECTED_PORTS; unset or invalid
    list refuses every port); caution ports (SWITCH_CAUTION_PORTS) need
    confirm_caution_port=true. dry_run=true (default) only shows the
    commands and current state. Does not save.
    """
    tool = "port_set_description"
    params = {
        "port": port, "text": text, "confirm_caution_port": confirm_caution_port,
        "dry_run": dry_run,
    }
    try:
        if not isinstance(dry_run, bool):
            raise ValidationError("dry_run must be true or false.")
        if not isinstance(confirm_caution_port, bool):
            raise ValidationError("confirm_caution_port must be true or false.")
        validate_port(port)
        if text is not None:
            validate_description(text)
        reject_protected_port(port, action=tool)
        warnings = []
        if require_caution_confirmation(port, confirmed=confirm_caution_port, action=tool):
            warnings.append(f"{port} is a caution port; confirmed with confirm_caution_port=true.")
        plan = writes.WritePlan(
            tool=tool,
            stages=[writes.Stage(build_description_commands(port, text))],
            readbacks=[READBACK_DESCRIPTION],
            expected=(
                f"description of {port} = {text!r}" if text is not None
                else f"description of {port} cleared"
            ),
            warnings=warnings,
        )
        output = writes.execute(plan, dry_run=dry_run)
        if not dry_run:
            data = json.loads(output)
            data["readback_note"] = description_readback_note(
                data.get("after", {}).get(READBACK_DESCRIPTION, ""), port, text
            )
            output = json.dumps(data, indent=2, ensure_ascii=False)
    except ValidationError as exc:
        return _fail(tool, params, f"Rejected: {exc}", allowed=False)
    except SwitchConnectionError as exc:
        return _fail(tool, params, f"Error: {exc}", allowed=True)
    return ok(tool, params, output, audit_result="dry run" if dry_run else "ok")


class _DryRunStop(BaseException):
    """Raised by _snmp_send in a dry run, before anything is sent.

    BaseException, so the generic ``except Exception`` rollback handlers in
    the SNMP tools do not catch it; the session still closes (finally)."""

    def __init__(self, commands: list[str]) -> None:
        super().__init__("dry run")
        self.commands = list(commands)


_SNMP_DRY_RUN: ContextVar[bool] = ContextVar("snmp_dry_run", default=False)
_SNMP_SNAPSHOT: ContextVar[dict[str, Any] | None] = ContextVar("snmp_snapshot", default=None)


def _snmp_send(conn: Any, commands: list[str], **kwargs: Any) -> str:
    """Send an SNMP config set, honoring dry run and the pre-write snapshot.

    In a dry run, all prechecks before the first send have passed when this
    raises. The snapshot is taken once, right before the first real send."""
    if _SNMP_DRY_RUN.get():
        raise _DryRunStop(commands)
    state = _SNMP_SNAPSHOT.get()
    if state is not None and "result" not in state:
        result = writes.take_snapshot(conn, state["tool"])
        result.pop("config", None)
        state["result"] = result
    return _send_config(conn, commands, **kwargs)


def _snmp_call(tool: str, params: dict[str, Any], dry_run: bool, impl: Any) -> str:
    """Run an SNMP tool implementation as dry run or for real."""
    if not isinstance(dry_run, bool):
        return _fail(tool, params, "Rejected: dry_run must be true or false.", allowed=False)
    flag = _SNMP_DRY_RUN.set(dry_run)
    snap = _SNMP_SNAPSHOT.set(None if dry_run else {"tool": tool})
    try:
        result = impl()
        state = _SNMP_SNAPSHOT.get()
    except _DryRunStop as stop:
        data = {
            "tool": tool,
            "dry_run": True,
            "sent": False,
            "commands": redact_command_list(stop.commands),
            "note": (
                "Dry run: the prechecks passed and nothing was sent. Later steps "
                "(read-back, rollback) are not listed. Call again with "
                "dry_run=false to apply."
            ),
        }
        return ok(tool, {**params, "dry_run": True},
                  redact_secrets(json.dumps(data, indent=2)), audit_result="dry run")
    finally:
        _SNMP_DRY_RUN.reset(flag)
        _SNMP_SNAPSHOT.reset(snap)
    if state is not None and isinstance(state.get("result"), dict):
        result += "\n\npre-write snapshot: " + json.dumps(state["result"])
    return result


def _snmp_exec(conn: Any, command: str) -> str:
    """Exec a show command; return raw device text. Caller must redact before returning."""
    return send_paged(conn, command)


def _snmp_syntax_note() -> str:
    return (
        "CLI syntax source: " + CLI_SOURCE + " "
        "These commands are not live-confirmed; have the network admin verify them "
        "before relying on the result."
    )


def _snmp_fail(tool: str, params: dict[str, Any], exc: BaseException, *, allowed: bool) -> str:
    prefix = "Rejected: " if isinstance(exc, ValidationError) and not allowed else "Error: "
    # ValidationError is already written without the secret; still redact.
    return _fail(tool, params, prefix + str(exc), allowed=allowed)


def _verification_failed(exc: BaseException) -> SwitchConnectionError:
    return SwitchConnectionError(
        "Configuration was sent, verification failed: " + redact_secrets(str(exc))
    )


def _reject_case_variant_view(views: list[ViewSubtree], view_name: str) -> None:
    variants = case_variant_view_names(views, view_name)
    if variants:
        note = case_variant_note(view_name, variants)
        raise ValidationError(note[:1].upper() + note[1:] + ". Use a distinct view name.")


def _precheck_read_view(conn: Any, view_name: str, oid: str) -> None:
    """Refuse a whole MIB subtree in a view that is (or looks like) a write view.

    Write views hold only the writable columns; adding e.g. the whole
    POWER-ETHERNET-MIB or ifTable there would widen write access. OIDs are
    compared by arcs after the central normalization (oid_arcs), so
    ``.1.3.6…`` or ``iso.3.6…`` spellings cannot hide a column; entries
    with an unparseable OID or a partial (wildcard) mask are refused.
    """
    label = "POWER-ETHERNET-MIB" if oid == POE_SUBTREE else f"subtree {oid}"
    accesses = parse_snmp_access(_snmp_exec(conn, READBACK_SNMP_ACCESS))
    if not accesses:
        raise ValidationError(
            "Could not parse show snmp group access (unknown table layout). "
            f"Refusing to add {label} until it is verified that "
            "the view is not used for write access."
        )
    # casefold here only widens the refusal (fail-closed); the viewtree
    # check below refuses case-only variants explicitly.
    if any(
        item.write_view.strip().casefold() == view_name.casefold() for item in accesses
    ):
        raise ValidationError(
            f"View {view_name!r} is used as a write view. {label} "
            "may only be added to a read view."
        )
    views = parse_snmp_viewtree(_snmp_exec(conn, READBACK_SNMP_VIEW))
    if not views:
        raise ValidationError(
            "Could not parse show snmp viewtree (unknown table layout). "
            f"Refusing to add {label} until the view is verified."
        )
    _reject_case_variant_view(views, view_name)
    problem = view_entry_problem(views, view_name)
    if problem:
        raise ValidationError(
            problem[:1].upper() + problem[1:] + f". Refusing to add {label}."
        )
    for item in views:
        if item.name != view_name:
            continue
        # Read views built by this server hold only included subtrees;
        # anything else (an exclusion, a writable column) is refused.
        if item.view_type not in {"included", "include"} or any(
            oid_within(item.oid, column) for column in WRITE_ALLOWED_SUBTREES
        ):
            raise ValidationError(
                f"View {view_name!r} has an excluded entry or a writable "
                f"column ({canonical_oid(item.oid)}), so it is a write view. "
                f"{label} may only be added to a read view."
            )


def _snmp_view_create_impl(view_name: str, subtree: str) -> str:
    """Add one allow-listed included subtree to an SNMP read view. Does not save.

    Gate this in the hub with unlock. subtree must be an OID or alias from
    the fixed allowlist (interfaces / ifmib / power-ethernet). Refused for
    any view used as a write view, holding a writable column or an
    excluded entry; build write views with snmp_write_view_create. The CLI syntax is not
    live-confirmed; see the README.
    """
    params = {"view_name": view_name, "subtree": subtree}
    try:
        require_snmp_write_enabled()
        view_name = validate_snmp_name(view_name, what="view name")
        oid = normalize_subtree(subtree)
        commands = build_view_create_commands(view_name, oid)

        def _run(conn: Any) -> str:
            _precheck_read_view(conn, view_name, oid)
            _snmp_send(conn, commands)
            try:
                view_out = _snmp_exec(conn, READBACK_SNMP_VIEW)
            except Exception as exc:  # noqa: BLE001 — must wrap any post-send failure
                raise _verification_failed(exc) from None
            present = any(
                item.name == view_name and canonical_oid(item.oid) == oid
                for item in parse_snmp_viewtree(view_out)
            )
            if present:
                note = f"Read-back check: view {view_name} includes {oid}."
            else:
                note = (
                    f"Read-back check: could not verify that view {view_name} "
                    f"includes {oid}. Confirm show snmp viewtree live; the "
                    "parser assumes ISS key: value blocks."
                )
            return (
                format_sent_commands(commands)
                + "\n\nConfiguration sent.\n"
                + f"--- {READBACK_SNMP_VIEW} ---\n"
                + redact_show_output(READBACK_SNMP_VIEW, view_out)
                + "\n\n"
                + note
                + "\n"
                + _snmp_syntax_note()
            )

        body = run_in_session(_run, enable_session_log=False)
    except ValidationError as exc:
        return _snmp_fail("snmp_view_create", params, exc, allowed=False)
    except SwitchConnectionError as exc:
        return _snmp_fail("snmp_view_create", params, exc, allowed=True)
    return _ok("snmp_view_create", params, redact_secrets(body))


def _snmp_write_view_create_impl(view_name: str, subtree: str) -> str:
    """Add one writable column to an SNMP write view. Does not save.

    Gate this in the hub with unlock. subtree must be ifAdminStatus
    (1.3.6.1.2.1.2.2.1.7), ifAlias (1.3.6.1.2.1.31.1.1.1.18) or
    pethPsePortAdminEnable (1.3.6.1.2.1.105.1.1.1.3, PoE on/off); whole
    MIB subtrees are never allowed in a write view. There are no per-port
    exclusions: anyone with a community bound to this view can write
    these columns for every port, including SWITCH_PROTECTED_PORTS. The
    command is sent with a "%" error check and verified in show snmp
    viewtree; on any failure the column is removed again
    (``no snmp view <view> <oid>``) and the viewtree must equal the state
    before. The CLI syntax is not live-confirmed.
    """
    params = {"view_name": view_name, "subtree": subtree}
    try:
        require_snmp_write_enabled()
        view_name = validate_snmp_name(view_name, what="view name")
        oid = normalize_write_subtree(subtree)

        def _run(conn: Any) -> str:
            _, before = _read_views(conn)
            if not before:
                raise ValidationError(
                    "Could not parse show snmp viewtree (unknown table layout). "
                    "Refusing to build a write view until the read-back can "
                    "be verified. Confirm the output format live."
                )
            _precheck_write_view_target(before, view_name)
            return _apply_write_view(conn, view_name, oid, before)

        body = run_in_session(_run, enable_session_log=False)
    except ValidationError as exc:
        return _snmp_fail("snmp_write_view_create", params, exc, allowed=False)
    except SwitchConnectionError as exc:
        return _snmp_fail("snmp_write_view_create", params, exc, allowed=True)
    return _ok("snmp_write_view_create", params, redact_secrets(body))


def _read_views(conn: Any) -> tuple[str, list[ViewSubtree]]:
    text = _snmp_exec(conn, READBACK_SNMP_VIEW)
    return text, parse_snmp_viewtree(text)


def _rollback_write_view(
    conn: Any, view_name: str, oid: str, before: list[ViewSubtree]
) -> str:
    """Remove the column this call added and verify the viewtree against ``before``.

    Linksys CLI: ``no snmp view <ViewName> <OIDTree>``.
    """
    send_note = ""
    try:
        _snmp_send(
            conn, [f"no snmp view {view_name} {oid}"], error_pattern=CONFIG_ERROR_PATTERN
        )
    except Exception:  # noqa: BLE001 — judged by the read-back
        send_note = " The switch reported an error for the removal."
    try:
        _, after = _read_views(conn)
        restored = bool(after) and view_entry_set(after) == view_entry_set(before)
    except Exception:  # noqa: BLE001 — an unreadable state is "not verified"
        restored = False
    if restored:
        return (
            f"Rolled back (removed {oid}); show snmp viewtree matches the "
            "state before this call." + send_note
        )
    return (
        f"ROLLBACK NOT VERIFIED (tried to remove {oid}): show snmp viewtree "
        f"does not match the state before this call. Check the view {view_name} "
        "and its community bindings (show snmp group access) on the switch "
        "now; do not bind a community to it." + send_note
    )


def _apply_write_view(
    conn: Any, view_name: str, oid: str, before: list[ViewSubtree]
) -> str:
    """Add the column (if missing) and verify the whole write view (fail-closed).

    The command is sent with error_pattern; the read-back must show a
    view that includes only writable columns, among them ``oid``. On any
    failure a column added by this call is removed again.
    """
    include_new = oid not in set(view_included_oids(before, view_name))
    commands = build_write_view_commands(view_name, oid) if include_new else []
    try:
        if commands:
            _snmp_send(conn, commands, error_pattern=CONFIG_ERROR_PATTERN)
        view_out, after = _read_views(conn)
        ok, note = view_is_write_safe(after, view_name)
        if not ok:
            raise ValidationError(note)
        if oid not in set(view_included_oids(after, view_name)):
            raise ValidationError(f"write view {view_name!r} does not include {oid}")
    except Exception as exc:  # noqa: BLE001 — every failure must roll back
        if not include_new:
            if isinstance(exc, ValidationError):
                raise ValidationError(
                    f"Nothing was sent: {exc}. Fix the view on the switch first."
                ) from None
            raise SwitchConnectionError(
                f"Nothing was sent; the read-back failed: {redact_secrets(str(exc))}"
            ) from None
        rollback = _rollback_write_view(conn, view_name, oid, before)
        raise SwitchConnectionError(
            "Configuration was sent, verification failed: "
            f"{redact_secrets(str(exc))}. {rollback}"
        ) from None

    head = (
        format_sent_commands(commands) + "\n\nConfiguration sent.\n"
        if commands
        else "Nothing to send: the column was already included.\n"
    )
    return (
        head
        + f"--- {READBACK_SNMP_VIEW} ---\n"
        + redact_show_output(READBACK_SNMP_VIEW, view_out)
        + "\n\nRead-back check: "
        + note
        + ".\n"
        + _snmp_syntax_note()
    )


def _precheck_write_view_target(views: list[ViewSubtree], view_name: str) -> None:
    """Refuse to turn a view with non-write subtrees (e.g. a whole MIB) into a write view.

    Also refuses a name that differs from an existing view only in case,
    and entries with an unparseable OID or a partial (wildcard) mask.
    """
    _reject_case_variant_view(views, view_name)
    problem = view_entry_problem(views, view_name)
    if problem:
        raise ValidationError(
            problem[:1].upper() + problem[1:] + ". Use a separate view name "
            "for the write view."
        )
    for item in views:
        if item.name != view_name:
            continue
        if item.view_type in {"excluded", "exclude"}:
            continue
        compact = canonical_oid(item.oid)
        if compact not in WRITE_ALLOWED_SUBTREES:
            raise ValidationError(
                f"View {view_name!r} already includes {compact}, which is "
                "not allowed in a write view. Use a separate view name for "
                "the write view."
            )


def _precheck_view_for_community(
    conn: Any, view_name: str, write_view: str | None = None
) -> None:
    views_text = _snmp_exec(conn, READBACK_SNMP_VIEW)
    views = parse_snmp_viewtree(views_text)
    if not views:
        raise ValidationError(
            "Could not parse show snmp viewtree (unknown table layout, or "
            "the view list is empty). Refusing to create a community until "
            "the view can be verified. Confirm the output format live."
        )
    names = {item.name for item in views}
    if view_name not in names:
        raise ValidationError(
            f"View {view_name!r} was not found in show snmp viewtree. "
            "Create it with snmp_view_create first."
        )
    ok, note = view_is_restricted(views, view_name)
    if not ok:
        raise ValidationError(
            note + ". Refusing to bind a community to a view that is not "
            "restricted to the OID allowlist."
        )
    if write_view is None:
        return
    ok, note = view_is_write_safe(views, write_view)
    if not ok:
        raise ValidationError(
            note[:1].upper()
            + note[1:]
            + ". Refusing to grant write access. Build the write view with "
            "snmp_write_view_create first."
        )


def _snmp_community_create_impl(
    view_name: str, access: str, write_view: str | None = None
) -> str:
    """Create a v2c community from SWITCH_SNMP_COMMUNITY, bound to views.

    view_name is the read view. access is 'ro' or 'rw'; 'rw' requires a
    separate write_view built with snmp_write_view_create (only the
    writable columns, no per-port exclusions). The secret is never
    a tool argument and is redacted as [REDACTED] in all output. Does not
    save. Gate with hub unlock. The CLI syntax is not live-confirmed; see
    the README.
    """
    params = {"view_name": view_name, "access": access, "write_view": write_view}
    try:
        require_snmp_write_enabled()
        view_name = validate_snmp_name(view_name, what="view name")
        access = validate_snmp_access(access)
        if write_view is not None:
            write_view = validate_snmp_name(write_view, what="write view name")
        community = validate_snmp_community_secret()
        commands = build_community_create_commands(
            view_name, access, community, write_view
        )

        def _run(conn: Any) -> str:
            _precheck_view_for_community(
                conn, view_name, write_view if access == "rw" else None
            )
            _snmp_send(conn, commands)
            try:
                community_out = _snmp_exec(conn, READBACK_SNMP_COMMUNITY)
                group_out = _snmp_exec(conn, READBACK_SNMP_GROUP)
                access_out = _snmp_exec(conn, READBACK_SNMP_ACCESS)
                view_out = _snmp_exec(conn, READBACK_SNMP_VIEW)
                status = assert_configured_community_ready(
                    community_output=community_out,
                    group_output=group_out,
                    access_output=access_out,
                    view_output=view_out,
                    community=community,
                    expected_read_view=view_name,
                    expected_write_view=write_view if access == "rw" else None,
                )
                return (
                    format_sent_commands(commands)
                    + "\n\nConfiguration sent.\n"
                    + f"--- {READBACK_SNMP_COMMUNITY} ---\n"
                    + redact_show_output(READBACK_SNMP_COMMUNITY, community_out)
                    + "\n"
                    + f"--- {READBACK_SNMP_GROUP} ---\n"
                    + redact_show_output(READBACK_SNMP_GROUP, group_out)
                    + "\n"
                    + f"--- {READBACK_SNMP_ACCESS} ---\n"
                    + redact_show_output(READBACK_SNMP_ACCESS, access_out)
                    + "\n"
                    + f"--- {READBACK_SNMP_VIEW} ---\n"
                    + redact_show_output(READBACK_SNMP_VIEW, view_out)
                    + "\n\n"
                    + "Read-back check: "
                    + status
                    + "\n"
                    + _snmp_syntax_note()
                )
            except Exception as exc:  # noqa: BLE001 — must wrap any post-send failure
                raise _verification_failed(exc) from None

        body = run_in_session(
            _run, enable_session_log=False
        )
    except ValidationError as exc:
        return _snmp_fail("snmp_community_create", params, exc, allowed=False)
    except SwitchConnectionError as exc:
        return _snmp_fail("snmp_community_create", params, exc, allowed=True)
    return _ok("snmp_community_create", params, redact_secrets(body))


def _snmp_community_remove_impl(name: str) -> str:
    """Remove an allow-listed default community (public or private).

    Refuses unless the configured SWITCH_SNMP_COMMUNITY community is
    present and mapped to a restricted allow-listed view. Never removes
    the configured community itself. Does not save. Gate with hub unlock.
    """
    params = {"name": name}
    try:
        require_snmp_write_enabled()
        community = validate_snmp_community_secret()
        requested = validate_community_remove_name(name, community)

        def _run(conn: Any) -> str:
            community_out = _snmp_exec(conn, READBACK_SNMP_COMMUNITY)
            group_out = _snmp_exec(conn, READBACK_SNMP_GROUP)
            access_out = _snmp_exec(conn, READBACK_SNMP_ACCESS)
            view_out = _snmp_exec(conn, READBACK_SNMP_VIEW)
            status = assert_configured_community_ready(
                community_output=community_out,
                group_output=group_out,
                access_output=access_out,
                view_output=view_out,
                community=community,
            )
            entries = parse_snmp_community(community_out)
            exact = resolve_removable_community_name(requested, entries, community)
            commands = build_community_remove_commands(exact)
            _snmp_send(conn, commands)
            try:
                after = _snmp_exec(conn, READBACK_SNMP_COMMUNITY)
                still = any(
                    (item.name.lower() == exact.lower())
                    or (item.index.lower() == exact.lower())
                    for item in parse_snmp_community(after)
                )
                if still:
                    note = (
                        f"Read-back check: {exact} is still present in "
                        "show snmp community after the no-command."
                    )
                else:
                    note = (
                        f"Read-back check: {exact} is no longer present in "
                        "show snmp community. "
                        + status
                    )
                return (
                    format_sent_commands(commands)
                    + "\n\n"
                    + status
                    + "\n\nConfiguration sent.\n"
                    + f"--- {READBACK_SNMP_COMMUNITY} ---\n"
                    + redact_show_output(READBACK_SNMP_COMMUNITY, after)
                    + "\n\n"
                    + note
                    + "\n"
                    + _snmp_syntax_note()
                )
            except Exception as exc:  # noqa: BLE001 — must wrap any post-send failure
                raise _verification_failed(exc) from None

        body = run_in_session(
            _run, enable_session_log=False
        )
    except ValidationError as exc:
        return _snmp_fail("snmp_community_remove", params, exc, allowed=False)
    except SwitchConnectionError as exc:
        return _snmp_fail("snmp_community_remove", params, exc, allowed=True)
    return _ok("snmp_community_remove", params, redact_secrets(body))


def _snmp_user_remove_impl(name: str) -> str:
    """Remove an allow-listed SNMP user (noAuthUser). Does not save.

    Gate this in the hub with unlock. The CLI syntax is not live-confirmed.
    """
    params = {"name": name}
    try:
        require_snmp_write_enabled()
        name = validate_user_remove_name(name)
        commands = build_user_remove_commands(name)

        def _run(conn: Any) -> str:
            before = _snmp_exec(conn, READBACK_SNMP_USER)
            if not user_present(before, name):
                return (
                    f"SNMP user {name} was not present in show snmp user; "
                    "no configuration was sent.\n"
                    f"--- {READBACK_SNMP_USER} ---\n"
                    + redact_show_output(READBACK_SNMP_USER, before)
                    + "\n"
                    + _snmp_syntax_note()
                )
            _snmp_send(conn, commands)
            try:
                after = _snmp_exec(conn, READBACK_SNMP_USER)
                if user_present(after, name):
                    note = (
                        f"Read-back check: {name} is still present in show snmp user."
                    )
                else:
                    note = (
                        f"Read-back check: {name} is no longer present in show snmp user."
                    )
                return (
                    format_sent_commands(commands)
                    + "\n\nConfiguration sent.\n"
                    + f"--- {READBACK_SNMP_USER} ---\n"
                    + redact_show_output(READBACK_SNMP_USER, after)
                    + "\n\n"
                    + note
                    + "\n"
                    + _snmp_syntax_note()
                )
            except Exception as exc:  # noqa: BLE001 — must wrap any post-send failure
                raise _verification_failed(exc) from None

        body = run_in_session(
            _run, enable_session_log=False
        )
    except ValidationError as exc:
        return _snmp_fail("snmp_user_remove", params, exc, allowed=False)
    except SwitchConnectionError as exc:
        return _snmp_fail("snmp_user_remove", params, exc, allowed=True)
    return _ok("snmp_user_remove", params, redact_secrets(body))


_DRY_RUN_DOC = (
    "\n\n    dry_run=true (default) runs the read-only prechecks and returns the "
    "commands the\n    first configuration step would send; nothing is sent."
)


def snmp_view_create(view_name: str, subtree: str, dry_run: bool = True) -> str:
    return _snmp_call(
        "snmp_view_create", {"view_name": view_name, "subtree": subtree}, dry_run,
        lambda: _snmp_view_create_impl(view_name, subtree),
    )


def snmp_write_view_create(view_name: str, subtree: str, dry_run: bool = True) -> str:
    return _snmp_call(
        "snmp_write_view_create", {"view_name": view_name, "subtree": subtree}, dry_run,
        lambda: _snmp_write_view_create_impl(view_name, subtree),
    )


def snmp_community_create(
    view_name: str, access: str, write_view: str | None = None, dry_run: bool = True
) -> str:
    return _snmp_call(
        "snmp_community_create",
        {"view_name": view_name, "access": access, "write_view": write_view},
        dry_run,
        lambda: _snmp_community_create_impl(view_name, access, write_view),
    )


def snmp_community_remove(name: str, dry_run: bool = True) -> str:
    return _snmp_call(
        "snmp_community_remove", {"name": name}, dry_run,
        lambda: _snmp_community_remove_impl(name),
    )


def snmp_user_remove(name: str, dry_run: bool = True) -> str:
    return _snmp_call(
        "snmp_user_remove", {"name": name}, dry_run, lambda: _snmp_user_remove_impl(name)
    )


for _public, _impl in (
    (snmp_view_create, _snmp_view_create_impl),
    (snmp_write_view_create, _snmp_write_view_create_impl),
    (snmp_community_create, _snmp_community_create_impl),
    (snmp_community_remove, _snmp_community_remove_impl),
    (snmp_user_remove, _snmp_user_remove_impl),
):
    _public.__doc__ = (_impl.__doc__ or "").rstrip() + _DRY_RUN_DOC


SAVE_SNAPSHOT_TAG = readtools.SAVED_TAG


def _running_for_save(dry_run: bool) -> tuple[str | None, list[str]]:
    """Masked running-config via the background dump, when save_config needs it.

    ``show current running-config`` is too slow to run inside the save
    session: it outlives the caller's request timeout, and
    ``save_config(dry_run=false)`` is not wrapped in the call budget (an
    applying write must not be cut mid-``save``). A client abort then
    leaves the worker thread and the SSH session running.

    The dump is the same background job as ``config_read``. If it is not
    finished within the call budget the caller gets ``Pending`` and
    ``save`` is not sent. When ``dry_run=false`` and
    ``SWITCH_PRE_WRITE_SNAPSHOT=off``, the dump is skipped.
    """
    if not dry_run and writes.snapshot_mode() == "off":
        return None, []
    try:
        dump = configdump.running_config()
    except SwitchConnectionError as exc:
        return None, [f"running-config unavailable: {exc}"]
    return dump.config, []


def _save_flow(
    conn: Any,
    dry_run: bool,
    running: str | None,
    warnings: list[str],
) -> dict[str, Any]:
    """save_config steps on one session (see save_config).

    ``running`` is the masked running-config from the background dump (or
    None). This session only sends ``save`` and ``show system information``;
    it does not re-read the running-config.

    The LGS CLI cannot show the startup-config, so the backup is the masked
    running-config that is about to be saved (tag pre-save). It is also the
    baseline for config_diff and for the next save's diff."""
    data: dict[str, Any] = {"tool": "save_config", "dry_run": dry_run}

    previous_path, previous = readtools.last_saved_copy()
    data["startup_config"] = "not readable on this device"
    data["previous_save_copy"] = previous_path

    def _system_status() -> str | None:
        return parse_system_information(
            send_paged_redacted(conn, "show system information")
        )["config_save_status"]

    if dry_run:
        if running is not None and previous is not None:
            data["diff_last_save_to_running"] = configstore.unified_diff(
                previous, running, before_label="last save (pre-save copy)",
                after_label="running-config",
            )
        elif running is not None:
            warnings.append(
                "No copy from an earlier save_config yet; no diff of what would change."
            )
        data["config_save_status"] = _system_status()
        data.update(sent=False, commands=["save"], warnings=warnings,
                    note="Dry run: nothing was saved. Call again with dry_run=false to save.")
        return data

    mode = writes.snapshot_mode()
    if mode == "off":
        data["backup"] = {"skipped": "SWITCH_PRE_WRITE_SNAPSHOT=off"}
    elif running is None:
        if mode == "required":
            raise SwitchConnectionError(
                "Backup of the running-config to be saved failed, nothing was saved: "
                + "; ".join(warnings)
                + " (set SWITCH_PRE_WRITE_SNAPSHOT=best-effort to save without it)."
            )
        data["backup"] = {"failed": "; ".join(warnings)}
    else:
        try:
            backup = configstore.store_backup(
                running, "running", tag=SAVE_SNAPSHOT_TAG, diff_same_tag=True
            )
        except OSError as exc:
            if mode == "required":
                raise SwitchConnectionError(
                    f"Backup not written, nothing was saved: {exc}"
                ) from None
            data["backup"] = {"failed": str(exc)}
        else:
            # The diff to the previous pre-save copy is what this save changes
            # compared with the last save through this server.
            data["diff_previous_save_to_saved"] = backup.pop("diff", None)
            data["backup"] = backup
    data["device_output"] = save_in_session(conn)
    try:
        data["config_save_status"] = _system_status()
    except Exception as exc:  # noqa: BLE001 - save already done; report only
        warnings.append(f"show system information failed: {redact_secrets(str(exc))}")
    data.update(sent=True, commands=["save"], warnings=warnings)
    return data


def save_config(dry_run: bool = True) -> str:
    """Copy running-config to startup-config (privileged exec 'save').

    The LGS CLI cannot show the startup-config. dry_run=true (default):
    masked diff from the running-config stored at the last save through
    this server to the current running-config, plus the Config Save Status;
    nothing is saved. dry_run=false: stores the masked running-config that
    is saved (SWITCH_BACKUP_DIR, tag pre-save; required unless
    SWITCH_PRE_WRITE_SNAPSHOT=best-effort/off), saves, returns the diff to
    the previous save copy and the Config Save Status. The running-config
    copy uses the same background dump as config_read: a slow dump answers
    Pending first; the next call saves. Gate with hub unlock.
    """
    params: dict[str, Any] = {"dry_run": dry_run}
    if not isinstance(dry_run, bool):
        return _fail("save_config", params, "Rejected: dry_run must be true or false.",
                     allowed=False)
    try:
        # The snapshot uses the call budget even for dry_run=false, so a
        # slow dump answers Pending (and closes nothing mid-save). The
        # actual 'save' runs afterwards without that deadline.
        if connection.remaining_budget() is None:
            with call_deadline():
                running, warnings = _running_for_save(dry_run)
        else:
            running, warnings = _running_for_save(dry_run)
        data = run_in_session(
            lambda conn: _save_flow(conn, dry_run, running, warnings),
            enable_session_log=False,
        )
    except configdump.ConfigDumpPending as exc:
        return _fail("save_config", params, f"Pending: {exc}", allowed=True)
    except (ValidationError, SwitchConnectionError) as exc:
        return _fail("save_config", params, f"Error: {exc}", allowed=True)
    return ok("save_config", params, json.dumps(data, indent=2, ensure_ascii=False),
              audit_result="dry run" if dry_run else "ok")


# Port write tools show the configured protected/caution ports in their
# description (read from the environment at start; nothing is hardcoded).
PORT_POLICY_TOOLS = frozenset(
    {
        "port_set_description", "port_enable", "port_disable", "poe_enable", "poe_disable",
        "poe_cycle", "port_security_set", "storm_control_set", "rate_limit_set",
        "cable_diag", "clear_counters",
    }
)


def tool_description(function: Any) -> str:
    """Docstring, plus the current port policy for port write tools."""
    doc = inspect.cleandoc(function.__doc__ or "")
    if function.__name__ in PORT_POLICY_TOOLS:
        doc = f"{doc}\n\n{port_policy_text()}"
    return doc


ALL_TOOLS = (
    show,
    port_overview,
    port_set_description,
    snmp_view_create,
    snmp_write_view_create,
    snmp_community_create,
    snmp_community_remove,
    snmp_user_remove,
    save_config,
    *readtools.READ_TOOLS,
    *writetools.WRITE_TOOLS,
)

# Tools whose "port" parameter is not a switch port (syslog UDP port).
NON_SWITCH_PORT_TOOLS = frozenset({"syslog_set"})


def _takes_switch_port(function: Any) -> bool:
    return (
        "port" in inspect.signature(function).parameters
        and function.__name__ not in NON_SWITCH_PORT_TOOLS
    )


def _is_applying_write(function: Any, kwargs: dict[str, Any]) -> bool:
    """True for a write tool called with dry_run=false."""
    parameter = inspect.signature(function).parameters.get("dry_run")
    if parameter is None:
        return False
    return kwargs.get("dry_run", parameter.default) is False


def tool_entry(function: Any) -> Any:
    """Wrap a tool for MCP registration (inside the audit wrapper).

    - A switch-port argument is canonicalised once, centrally
      (``Gi0/15`` -> ``0/15``), before validation and the protected /
      caution port checks see it.
    - Every call except an applying write (dry_run=false) runs under the
      call budget (SWITCH_CALL_BUDGET), so it ends as a tool error before
      the caller's request timeout instead of holding the session.
      Applying writes keep the idle timeout only: a write must not be cut
      between sending and its read-back.
    """
    takes_port = _takes_switch_port(function)

    @functools.wraps(function)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if takes_port and "port" in kwargs:
            kwargs["port"] = canonical_port(kwargs["port"])
        if _is_applying_write(function, kwargs):
            return function(*args, **kwargs)
        try:
            seconds = call_budget()
        except ValidationError as exc:
            return f"Error: {exc}"
        with call_deadline(seconds):
            return function(*args, **kwargs)

    return wrapper


for _function in ALL_TOOLS:
    mcp.tool(name=_function.__name__, description=tool_description(_function))(
        audited_call(tool_entry(_function))
    )


def _install_signal_handlers() -> None:
    """Log out of the switch on SIGTERM/SIGHUP too (hub stop, restart),
    not only on a normal end of stdin; atexit covers interpreter exit."""
    atexit.register(connection.shutdown)

    def _stop(signum: int, _frame: Any) -> None:
        connection.shutdown()
        raise SystemExit(128 + signum)

    for name in ("SIGTERM", "SIGHUP"):
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, _stop)
        except (ValueError, OSError):  # not the main thread / not supported
            pass


def main() -> None:
    """Start the stdio MCP server. Does not open an SSH session.

    On exit the kept SSH session is logged out (graceful shutdown).
    """
    prepare_runtime()
    startup_checks()
    _install_signal_handlers()
    try:
        mcp.run(transport="stdio")
    finally:
        connection.shutdown()


if __name__ == "__main__":
    main()
