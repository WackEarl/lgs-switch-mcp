"""SSH session handling, pager handling, and CLI sequence runners.

No connection is opened at import or process start. Each tool call opens one
session (port_overview included), holds a process-wide lock for the duration,
and disconnects after.

Parser helpers live in ``parser``, command builders in ``commands``, and
``SwitchConnectionError`` in ``errors``. This module remains the session
layer and the public import path.
"""

from __future__ import annotations

import os
import re
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from netmiko import ConnectHandler

from netmiko_mcp_linksys.commands import (
    READBACK_DESCRIPTION,
    READBACK_INTERFACE,
    READBACK_POE,
    build_admin_state_commands,
    build_description_commands,
    build_poe_commands,
)
from netmiko_mcp_linksys.errors import SwitchConnectionError, wrap_transport_error
from netmiko_mcp_linksys.parser import (
    MAX_PAGES,
    PAGE_BREAK,
    PAGER_RE,
    clean_output,
    prompt_regex,
    visible_tail,
)
from netmiko_mcp_linksys.redaction import redact_device_text, redact_sensitive_lines
from netmiko_mcp_linksys.snmp_cli import (
    redact_community_listing,
    redact_community_name_fields,
)
from netmiko_mcp_linksys.validation import (
    ValidationError,
    config_output_is_error,
    redact_secrets,
)

# Backward-compatible alias; new code should use SwitchConnectionError.
ConnectionError = SwitchConnectionError

_LOCK = threading.Lock()

DEFAULT_READ_TIMEOUT = 60.0
MAX_READ_TIMEOUT = 600.0

# Best-effort paging-off for the Aricent/ISS-based LGS CLI. On ISS-family
# firmware this is a Global Configuration command (it is rejected in
# privileged exec, which is what the 0.1.0 live test hit). The result is not
# trusted: the pager loop below handles paging either way.
PAGING_OFF_CONFIG = ("set cli pagination off",)

# Y/N confirmation at the end of the last visible line, e.g. "(y/n)",
# "[Y/N]:", "(yes/no)?". The LGS328PC save prompt text is NOT live-confirmed
# (issue #4). Only this shape is answered, and only once; anything else
# runs into the idle timeout and fails without an answer (fail-closed).
SAVE_CONFIRM_RE = re.compile(
    r"(?:\(\s*y(?:es)?\s*/\s*n(?:o)?\s*\)|\[\s*y(?:es)?\s*/\s*n(?:o)?\s*\])\s*[:?]?\s*$",
    re.IGNORECASE,
)
SAVE_CONFIRM_ANSWER = "y"

_warned: set[str] = set()


def warn(message: str, *, once_key: str | None = None) -> None:
    """Write a redacted warning to stderr (stdout is the MCP channel)."""
    if once_key is not None:
        if once_key in _warned:
            return
        _warned.add(once_key)
    print(f"netmiko-mcp-linksys: warning: {redact_secrets(message)}", file=sys.stderr, flush=True)


def read_timeout() -> float:
    raw = (os.environ.get("SWITCH_READ_TIMEOUT") or "").strip()
    if not raw:
        return DEFAULT_READ_TIMEOUT
    try:
        value = float(raw)
    except ValueError:
        raise ValidationError(
            f"SWITCH_READ_TIMEOUT must be a number of seconds, got {raw!r}."
        ) from None
    if not 1 <= value <= MAX_READ_TIMEOUT:
        raise ValidationError(
            f"SWITCH_READ_TIMEOUT must be between 1 and {int(MAX_READ_TIMEOUT)} seconds."
        )
    return value


def paging_off_enabled() -> bool:
    raw = (os.environ.get("SWITCH_PAGING_OFF") or "1").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def prepare_private_file(path_str: str) -> Path:
    """Create (if needed) an append-only file with mode 0600, or raise OSError."""
    path = Path(path_str).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    created = not path.exists()
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        if created:
            os.chmod(path, 0o600)
    finally:
        os.close(fd)
    return path


def session_log_path() -> str | None:
    """Return a writable SWITCH_SESSION_LOG path, or None (never raises)."""
    raw = (os.environ.get("SWITCH_SESSION_LOG") or "").strip()
    if not raw:
        return None
    try:
        return str(prepare_private_file(raw))
    except OSError as exc:
        warn(
            f"SWITCH_SESSION_LOG {raw} is not writable ({exc}); session log disabled.",
            once_key=f"session-log:{raw}",
        )
        return None


def _commands_include_snmp_community(commands: list[str]) -> bool:
    return any(re.search(r"(?i)\bsnmp\s+community\b", command) for command in commands)


# Whitespace normalization matches the show-tool command filter
# (" ".join(command.split())). "sh" is the shortest show prefix; kind
# prefixes start at 2 characters so "co"/"vi"/"us" are fail-closed without
# also matching unrelated tokens such as "group".
_MIN_SHOW_PREFIX = 2
_MIN_SENSITIVE_KIND_PREFIX = 2
_SENSITIVE_SNMP_KINDS = ("community", "viewtree", "user")


def _normalized_command_words(command: str) -> list[str]:
    """Collapse ASCII whitespace like validate_command, then lower-case."""
    return " ".join(command.split()).lower().split()


def _is_command_prefix(submitted: str, full: str, *, min_len: int) -> bool:
    return len(submitted) >= min_len and full.startswith(submitted)


def _snmp_sensitive_kind(command: str) -> str | None:
    """Return community/viewtree/user if this is a sensitive SNMP show.

    Accepts abbreviated first and kind words (``sh snmp comm``) by prefix,
    case-insensitively, with any extra trailing words. ``snmp`` itself is
    matched in full.
    """
    words = _normalized_command_words(command)
    if len(words) < 3:
        return None
    show_w, snmp_w, kind = words[0], words[1], words[2]
    if not _is_command_prefix(show_w, "show", min_len=_MIN_SHOW_PREFIX):
        return None
    if snmp_w != "snmp":
        return None
    for full in _SENSITIVE_SNMP_KINDS:
        if _is_command_prefix(kind, full, min_len=_MIN_SENSITIVE_KIND_PREFIX):
            return full
    return None


def _is_snmp_sensitive_show(command: str) -> bool:
    return _snmp_sensitive_kind(command) is not None


def _is_strict_show(command: str) -> bool:
    """``show radius …`` (any abbreviation of show) uses strict line redaction."""
    words = _normalized_command_words(command)
    return (
        len(words) >= 2
        and _is_command_prefix(words[0], "show", min_len=_MIN_SHOW_PREFIX)
        and _is_command_prefix(words[1], "radius", min_len=3)
    )


def redact_show_output(command: str, text: str) -> str:
    """Redact secrets in exec output.

    Community listings are fully masked; every output then goes through the
    fail-closed line rules (``redaction``), strict for ``show radius``.
    """
    if _snmp_sensitive_kind(command) == "community":
        text = redact_community_listing(text)
    else:
        text = redact_secrets(text)
    return redact_sensitive_lines(text, strict=_is_strict_show(command))


def redact_session_log_file() -> None:
    """Rewrite SWITCH_SESSION_LOG so a community echo cannot remain in clear text.

    Called after the netmiko session is disconnected. Failures are
    warnings only; they never raise.
    """
    raw = (os.environ.get("SWITCH_SESSION_LOG") or "").strip()
    if not raw:
        return
    path = Path(raw).expanduser()
    if not path.is_file():
        return
    try:
        original = path.read_text(encoding="utf-8", errors="replace")
        # Do not use listing fail-closed here: a session log is not a
        # show snmp community table and must not be replaced wholesale.
        # Label-regex still masks Community Name fields (including
        # communities that are not the configured secret).
        redacted = redact_sensitive_lines(
            redact_community_name_fields(redact_secrets(original))
        )
        if redacted == original:
            return
        path.write_text(redacted, encoding="utf-8")
        os.chmod(path, 0o600)
    except OSError as exc:
        warn(
            f"SWITCH_SESSION_LOG could not be redacted ({exc}).",
            once_key=f"session-log-redact:{raw}",
        )


def connect_params(*, enable_session_log: bool = True) -> dict[str, Any]:
    host = (os.environ.get("SWITCH_HOST") or "").strip()
    username = (os.environ.get("SWITCH_USER") or "").strip()
    password = os.environ.get("SWITCH_PASSWORD") or ""
    device_type = (os.environ.get("SWITCH_DEVICE_TYPE") or "cisco_s300").strip() or "cisco_s300"
    known_hosts = (os.environ.get("SWITCH_KNOWN_HOSTS") or "").strip()

    missing = [
        name
        for name, value in (
            ("SWITCH_HOST", host),
            ("SWITCH_USER", username),
            ("SWITCH_PASSWORD", password),
            ("SWITCH_KNOWN_HOSTS", known_hosts),
        )
        if not value
    ]
    if missing:
        raise ValidationError(
            "Missing required environment variable(s): " + ", ".join(missing)
        )
    if not Path(known_hosts).expanduser().is_file():
        raise ValidationError(
            f"SWITCH_KNOWN_HOSTS file does not exist: {known_hosts}"
        )

    params: dict[str, Any] = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "use_keys": False,
        "allow_agent": False,
        "ssh_strict": True,
        "system_host_keys": False,
        "alt_host_keys": True,
        "alt_key_file": str(Path(known_hosts).expanduser()),
        "conn_timeout": 15,
        "auth_timeout": 20,
        "fast_cli": False,
        "read_timeout_override": read_timeout(),
    }
    log_path = session_log_path() if enable_session_log else None
    if log_path is not None:
        # netmiko masks the password/secret in the session log (no_log), and
        # only channel reads are recorded (record_writes stays False).
        params["session_log"] = log_path
        params["session_log_file_mode"] = "append"
        params["session_log_record_writes"] = False
    return params


def disable_paging_best_effort(conn: Any) -> None:
    """Try the ISS paging-off command; never fail the tool call because of it."""
    if not paging_off_enabled():
        return
    try:
        output = conn.send_config_set(
            list(PAGING_OFF_CONFIG),
            exit_config_mode=True,
            cmd_verify=False,
            read_timeout=read_timeout(),
        )
    except Exception as exc:
        warn(f"paging-off sequence failed ({exc}); relying on pager handling.", once_key="paging")
        return
    if config_output_is_error(str(output), commands=list(PAGING_OFF_CONFIG)):
        warn(
            "switch rejected 'set cli pagination off'; relying on pager handling.",
            once_key="paging",
        )


@contextmanager
def session(*, enable_session_log: bool = True) -> Iterator[Any]:
    """Yield a connected ConnectHandler, exclusive to one caller at a time.

    SNMP write tools pass enable_session_log=False so a community echo
    cannot sit in the session log in the clear until disconnect.
    cisco_s300 session_preparation already sends terminal width 511.
    """
    params = connect_params(enable_session_log=enable_session_log)
    with _LOCK:
        conn = None
        try:
            conn = ConnectHandler(**params)
            disable_paging_best_effort(conn)
            yield conn
        except ValidationError:
            raise
        except SwitchConnectionError:
            raise
        except Exception as exc:
            raise wrap_transport_error(exc) from None
        finally:
            if conn is not None:
                try:
                    conn.disconnect()
                except Exception:
                    pass
            redact_session_log_file()


def send_paged(
    conn: Any,
    command: str,
    *,
    timeout: float | None = None,
    poll_interval: float = 0.1,
    confirm: tuple[re.Pattern[str], str] | None = None,
) -> str:
    """Send one exec command and read until the prompt, paging through pagers.

    Each time the last visible line matches PAGER_RE a single space is sent.
    Finishes when the last visible line is the device prompt. ``timeout`` is
    an idle timeout: the seconds allowed without any new output.

    ``confirm=(pattern, answer)`` answers one confirmation prompt (last
    visible line matches ``pattern``) with ``answer``. A second
    confirmation prompt is not answered and raises SwitchConnectionError.
    """
    limit = read_timeout() if timeout is None else timeout
    prompt_re = prompt_regex(conn)
    try:
        conn.clear_buffer()
    except Exception:
        pass
    conn.write_channel(command + getattr(conn, "RETURN", "\n"))
    buffer = ""
    scan_from = 0
    pages = 0
    confirms = 0
    deadline = time.monotonic() + limit
    while True:
        chunk = conn.read_channel()
        if chunk:
            buffer += chunk
            deadline = time.monotonic() + limit
            tail = visible_tail(buffer[scan_from:])
            if PAGER_RE.search(tail):
                pages += 1
                if pages > MAX_PAGES:
                    raise SwitchConnectionError(f"Gave up after {MAX_PAGES} pager pages for {command!r}.")
                # Drop the pager line itself; PAGER_RE in clean_output is only
                # a fallback for prompts that are echoed elsewhere.
                cut = buffer.rfind("\n", scan_from)
                buffer = buffer[: cut + 1] if cut >= 0 else buffer[:scan_from]
                buffer += PAGE_BREAK
                conn.write_channel(" ")
                scan_from = len(buffer)
                continue
            if confirm is not None and confirm[0].search(tail):
                confirms += 1
                if confirms > 1:
                    raise SwitchConnectionError(
                        f"Unexpected second confirmation prompt after {command!r}; "
                        f"not answered (last line: {redact_secrets(tail[-80:])!r})."
                    )
                conn.write_channel(confirm[1] + getattr(conn, "RETURN", "\n"))
                scan_from = len(buffer)
                continue
            if "\n" in buffer and prompt_re.search(tail):
                return clean_output(buffer, command, prompt_re)
        elif time.monotonic() > deadline:
            if _is_snmp_sensitive_show(command):
                # Fail closed: do not echo a possibly secret last line
                # (foreign community, or unknown user-key layout).
                raise SwitchConnectionError(
                    f"No prompt after {command!r} ({limit:g}s without new output, "
                    f"pages: {pages})."
                )
            last = visible_tail(buffer)[-80:]
            raise SwitchConnectionError(
                f"No prompt after {command!r} ({limit:g}s without new output, "
                f"pages: {pages}, last line: {redact_show_output(command, last)!r})."
            )
        else:
            time.sleep(poll_interval)


SEQUENCE_SKIPPED = "not run: an earlier command in the same session failed"


def run_show_sequence(commands: list[str]) -> list[tuple[str, str | None, str | None]]:
    """Run several exec commands in one session, in order.

    Returns ``(command, output, error)`` per command; exactly one of output
    and error is set. After the first failing command the remaining ones are
    not sent (the channel state is unknown) and get ``SEQUENCE_SKIPPED``.
    Connect failures raise ``SwitchConnectionError`` / ``ValidationError`` as
    ``run_show`` does. Callers must pass only filtered show commands.
    """
    results: list[tuple[str, str | None, str | None]] = []
    # As run_shows: keep community / viewtree / user listings out of the
    # netmiko session log.
    enable_session_log = not any(_is_snmp_sensitive_show(command) for command in commands)
    with session(enable_session_log=enable_session_log) as conn:
        failed = False
        for command in commands:
            if failed:
                results.append((command, None, SEQUENCE_SKIPPED))
                continue
            try:
                results.append((command, _send_show(conn, command), None))
            except SwitchConnectionError as exc:
                failed = True
                results.append((command, None, redact_secrets(str(exc))))
    return results


def _send_show(conn: Any, command: str) -> str:
    """send_paged_redacted (pager, secret and community redaction) with every
    failure turned into a redacted SwitchConnectionError."""
    try:
        return send_paged_redacted(conn, command)
    except SwitchConnectionError:
        raise
    except Exception as exc:  # noqa: BLE001 - converted, redacted, re-raised (as run_show)
        raise wrap_transport_error(exc) from None


def send_paged_redacted(conn: Any, command: str) -> str:
    """send_paged, then redact secrets (and community listings)."""
    return redact_show_output(command, send_paged(conn, command))


def run_show(command: str) -> str:
    # Community / viewtree / user listings can contain secrets; do not
    # leave them in the netmiko session log until disconnect.
    enable_session_log = not _is_snmp_sensitive_show(command)
    with session(enable_session_log=enable_session_log) as conn:
        return send_paged_redacted(conn, command)


def run_shows(commands: list[str]) -> dict[str, str]:
    """Run several exec commands in one session; values are already redacted."""
    enable_session_log = not any(_is_snmp_sensitive_show(command) for command in commands)
    with session(enable_session_log=enable_session_log) as conn:
        return {command: send_paged_redacted(conn, command) for command in commands}


# A CLI error line on ISS starts with "%" ("% Invalid input", "% Error").
CONFIG_ERROR_PATTERN = r"%"


def _send_config(
    conn: Any, commands: list[str], *, error_pattern: str | None = None
) -> str:
    """Send a config set. With ``error_pattern``, netmiko stops at the first
    command whose output matches it, so later commands are never sent."""
    kwargs: dict[str, Any] = {}
    if error_pattern is not None:
        kwargs["error_pattern"] = error_pattern
    try:
        output = conn.send_config_set(
            commands,
            exit_config_mode=True,
            cmd_verify=True,
            read_timeout=read_timeout(),
            **kwargs,
        )
    except Exception as exc:
        if _commands_include_snmp_community(commands):
            # Never return or log str(exc): netmiko cmd_verify timeouts
            # embed repr(re.escape(command)), which bypasses exact redaction.
            raise SwitchConnectionError(
                "Device rejected the configuration sequence "
                f"({type(exc).__name__}). The exception text is omitted "
                "because the sequence may include a community string."
            ) from None
        raise wrap_transport_error(exc) from None
    text = output if isinstance(output, str) else str(output)
    if config_output_is_error(text, commands=commands):
        if _commands_include_snmp_community(commands):
            # Never return or audit device text: wrap, ANSI erase, or a
            # mid-line prompt redraw can split a community token so span
            # and exact redaction miss fragments.
            raise SwitchConnectionError(
                "Device rejected the configuration sequence. "
                "The device output is omitted because the sequence may "
                "include a community string."
            )
        raise SwitchConnectionError(
            "Device rejected the configuration sequence:\n" + redact_device_text(text)
        )
    return redact_device_text(text)


def run_config_set(commands: list[str]) -> str:
    with session() as conn:
        return _send_config(conn, commands)


def run_config_and_readback(commands: list[str], readback: str) -> str:
    """Apply a config set, then read the resulting state in the same session."""
    with session() as conn:
        _send_config(conn, commands)
        try:
            state_text = send_paged(conn, readback)
        except Exception as exc:
            raise wrap_transport_error(
                exc,
                message=(
                    "Configuration was sent, but read-back failed: "
                    + redact_secrets(str(exc))
                ),
            ) from None
        return (
            "Configuration sent.\n"
            f"--- {readback} ---\n"
            f"{redact_show_output(readback, state_text)}"
        )


def run_config_and_readbacks(
    commands: list[str],
    readbacks: list[str],
    *,
    enable_session_log: bool = True,
) -> str:
    """Apply a config set, then run one or more exec read-backs in the same session."""
    with session(enable_session_log=enable_session_log) as conn:
        _send_config(conn, commands)
        sections: list[str] = ["Configuration sent."]
        for readback in readbacks:
            try:
                state_text = send_paged_redacted(conn, readback)
            except SwitchConnectionError as exc:
                raise SwitchConnectionError(
                    "Configuration was sent, but read-back failed: "
                    + redact_secrets(str(exc))
                ) from None
            sections.append(f"--- {readback} ---\n{state_text}")
        return "\n".join(sections)


def run_in_session(
    callback: Any,
    *,
    enable_session_log: bool = True,
) -> Any:
    """Run ``callback(conn)`` inside a locked session. Output must be redacted by the caller if needed."""
    with session(enable_session_log=enable_session_log) as conn:
        return callback(conn)


def save_in_session(conn: Any) -> str:
    """Send 'save' on an open session; answer one Y/N confirmation with 'y'
    (prompt not live-confirmed)."""
    try:
        text = send_paged(conn, "save", confirm=(SAVE_CONFIRM_RE, SAVE_CONFIRM_ANSWER))
    except Exception as exc:
        # SwitchConnectionError messages are already redacted; redact again
        # for anything else (idempotent).
        raise wrap_transport_error(
            exc,
            message=(
                f"save did not complete: {redact_secrets(str(exc))} Whether "
                "startup-config was written is unknown; check it before "
                "saving again."
            ),
        ) from None
    if config_output_is_error(text, commands=["save"]):
        raise SwitchConnectionError("save failed:\n" + redact_device_text(text))
    return redact_device_text(text)


def run_save() -> str:
    """Send 'save' in its own session (see save_in_session)."""
    with session() as conn:
        return save_in_session(conn)


# Ctrl-U clears the typed line on ISS/Cisco-style CLIs.
CLEAR_LINE = "\x15"
HELP_IDLE_SECONDS = 2.0


def send_help(conn: Any, text: str, *, idle: float = HELP_IDLE_SECONDS) -> str:
    """Type ``text`` followed by ``?`` (no Enter), read the help listing,
    then clear the line with Ctrl-U and return to a clean prompt.

    Nothing is executed: the line is never submitted. The listing is read
    until ``idle`` seconds pass without new output (help prompts redraw
    the typed line, so the normal prompt check does not apply). Pager
    prompts are answered with a space. The caller must redact the result.
    """
    prompt_re = prompt_regex(conn)
    try:
        conn.clear_buffer()
    except Exception:
        pass
    conn.write_channel(f"{text} ?")
    buffer = ""
    pages = 0
    hard_deadline = time.monotonic() + read_timeout()
    last_output = time.monotonic()
    while True:
        chunk = conn.read_channel()
        now = time.monotonic()
        if chunk:
            buffer += chunk
            last_output = now
            if PAGER_RE.search(visible_tail(buffer)):
                pages += 1
                if pages > MAX_PAGES:
                    break
                conn.write_channel(" ")
            continue
        if now - last_output >= idle or now > hard_deadline:
            break
        time.sleep(0.1)
    # Clear the redrawn partial line, then get a fresh prompt.
    conn.write_channel(CLEAR_LINE)
    conn.write_channel(getattr(conn, "RETURN", "\n"))
    settle = time.monotonic() + read_timeout()
    tail = ""
    while time.monotonic() < settle:
        chunk = conn.read_channel()
        if chunk:
            tail += chunk
            if prompt_re.search(visible_tail(tail)):
                break
        else:
            time.sleep(0.1)
    text_out = clean_output(buffer, f"{text} ?", prompt_re)
    lines = [
        line
        for line in text_out.splitlines()
        if not (prompt_re.search(line) or line.strip().endswith(text.strip()))
    ]
    return "\n".join(lines).strip("\n")


__all__ = [
    "CONFIG_ERROR_PATTERN",
    "ConnectionError",
    "DEFAULT_READ_TIMEOUT",
    "MAX_PAGES",
    "MAX_READ_TIMEOUT",
    "PAGE_BREAK",
    "PAGER_RE",
    "PAGING_OFF_CONFIG",
    "READBACK_DESCRIPTION",
    "READBACK_INTERFACE",
    "READBACK_POE",
    "SAVE_CONFIRM_ANSWER",
    "SAVE_CONFIRM_RE",
    "SEQUENCE_SKIPPED",
    "SwitchConnectionError",
    "build_admin_state_commands",
    "build_description_commands",
    "build_poe_commands",
    "clean_output",
    "connect_params",
    "disable_paging_best_effort",
    "paging_off_enabled",
    "prepare_private_file",
    "read_timeout",
    "redact_session_log_file",
    "redact_show_output",
    "run_config_and_readback",
    "run_config_and_readbacks",
    "run_config_set",
    "run_in_session",
    "run_save",
    "save_in_session",
    "send_help",
    "run_show",
    "run_show_sequence",
    "run_shows",
    "send_paged",
    "send_paged_redacted",
    "session",
    "session_log_path",
    "warn",
    "wrap_transport_error",
]
