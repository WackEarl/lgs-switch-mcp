"""0.3.0 read tools. Registered on the MCP server in ``server``.

Parsed tools run hardcoded show commands through the same netmiko-mcp
allowlist as the show tool, in one session, on redacted text, and return
JSON. Parsers are best effort (the LGS table layouts are not recorded
yet): every result carries ``parse_warnings``; ``include_raw=true`` adds
the redacted device text.
"""

from __future__ import annotations

import json
import re
from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from netmiko_mcp_linksys import configstore, tables
from netmiko_mcp_linksys.audit import audit_path
from netmiko_mcp_linksys.connection import (
    SwitchConnectionError,
    run_in_session,
    run_show_sequence,
    send_help,
    send_paged_redacted,
)
from netmiko_mcp_linksys.redaction import redact_device_text
from netmiko_mcp_linksys.toolkit import (
    COMMAND_FILE_MISSING,
    command_file_ready,
    fail,
    filter_commands,
    ok,
    to_json,
)
from netmiko_mcp_linksys.validation import (
    ValidationError,
    redact_secrets,
    validate_int,
    validate_port,
)
from netmiko_mcp_linksys.writes import ConfigUnavailableError, read_config

COUNTERS_STATE = "counters.json"
AUDIT_TAIL_MAX = 500

SHOW_SYSTEM = "show system information"
SHOW_POWER_DETAIL = "show power detail"
SHOW_POWER_INLINE = "show power inline"
SHOW_STATUS = "show interfaces status"
SHOW_COUNTERS = "show interfaces counters"
SHOW_LOGGING = "show logging"
SHOW_DESCRIPTION = "show interfaces description"
SHOW_VLAN = "show vlan"
SHOW_LLDP = "show lldp neighbors"
SHOW_MAC = "show mac-address-table"
SHOW_MAC_COUNT = "show mac-address-table count"
SHOW_TEMPERATURE = "show device temperature"
SHOW_FAN = "show system fan status"
SHOW_UTILIZATION = "show system utilization"
ENVIRONMENT_SHOWS = {
    "temperature": SHOW_TEMPERATURE,
    "fan": SHOW_FAN,
    "utilization": SHOW_UTILIZATION,
}


class _Reads:
    """Outcome of one bundle: redacted outputs by command plus errors."""

    def __init__(self) -> None:
        self.outputs: dict[str, str] = {}
        self.errors: list[str] = []

    def get(self, command: str) -> str | None:
        return self.outputs.get(command)


def _read_bundle(commands: list[str]) -> _Reads:
    reads = _Reads()
    allowed, reads.errors = filter_commands(commands)
    if not allowed:
        return reads
    try:
        results = run_show_sequence([normalized for _, normalized in allowed])
    except (ValidationError, SwitchConnectionError) as exc:
        message = redact_secrets(str(exc))
        reads.errors.extend(f"{command}: {message}" for command, _ in allowed)
        return reads
    for (command, _), (_, output, error) in zip(allowed, results, strict=True):
        if error is not None:
            reads.errors.append(f"{command}: {redact_secrets(error)}")
        else:
            reads.outputs[command] = output or ""
    return reads


def _respond(tool: str, params: dict[str, Any], reads: _Reads, data: dict[str, Any],
             *, include_raw: bool) -> str:
    if not reads.outputs:
        return fail(tool, params, "Error: " + " | ".join(reads.errors or ["no output"]),
                    allowed=True)
    data["errors"] = reads.errors
    if include_raw:
        data["raw"] = reads.outputs
    return ok(tool, params, to_json(data))


def _check_bool(value: object, name: str) -> None:
    if not isinstance(value, bool):
        raise ValidationError(f"{name} must be true or false.")


def _guard(tool: str, params: dict[str, Any]) -> str | None:
    if not command_file_ready():
        return fail(tool, params, COMMAND_FILE_MISSING, allowed=False)
    return None


# ---------------------------------------------------------- health_summary


def health_summary(log_entries: int = 10, include_raw: bool = False) -> str:
    """Daily health view in one session, as JSON: uptime, config save status,
    PoE budget/consumption, ports up/down with speed/duplex, only ports with
    error/discard counters > 0, the last log entries, and temperature, fan
    and CPU/memory load (show device temperature, show system fan status, show
    system utilization) when the allowlist has them."""
    tool = "health_summary"
    params = {"log_entries": log_entries, "include_raw": include_raw}
    if (refusal := _guard(tool, params)) is not None:
        return refusal
    try:
        validate_int(log_entries, name="log_entries", low=0, high=100)
        _check_bool(include_raw, "include_raw")
    except ValidationError as exc:
        return fail(tool, params, f"Rejected: {exc}", allowed=False)
    # The environment shows are new in 0.3.1: a commands.yml without them
    # just leaves the section out instead of reporting rejections.
    environment_allowed, _ = filter_commands(list(ENVIRONMENT_SHOWS.values()))
    reads = _read_bundle(
        [SHOW_SYSTEM, SHOW_POWER_DETAIL, SHOW_POWER_INLINE, SHOW_STATUS, SHOW_COUNTERS, SHOW_LOGGING,
         *(command for command, _ in environment_allowed)]
    )
    warnings: list[str] = []
    data: dict[str, Any] = {"time": datetime.now(UTC).isoformat()}
    if (text := reads.get(SHOW_SYSTEM)) is not None:
        system = tables.parse_system_information(text)
        data["uptime"] = system["uptime"]
        data["config_save_status"] = system["config_save_status"]
    poe: dict[str, Any] = {}
    if (text := reads.get(SHOW_POWER_DETAIL)) is not None:
        detail = tables.parse_power_detail(text)
        poe["budget_w"] = detail["budget_w"]
        poe["consumed_w"] = detail["consumed_w"]
    if (text := reads.get(SHOW_POWER_INLINE)) is not None:
        ports, notes = tables.parse_power_inline(text)
        warnings += notes
        poe["ports_w"] = {
            port: info["power_w"] for port, info in ports.items() if info.get("power_w")
        }
    data["poe"] = poe
    if (text := reads.get(SHOW_STATUS)) is not None:
        status, notes = tables.parse_interfaces_status(text)
        warnings += notes
        data["ports_up"] = sorted((p for p, i in status.items() if i["link"] == "up"), key=_port_key)
        data["ports_down"] = sorted(
            (p for p, i in status.items() if i["link"] == "down"), key=_port_key
        )
        data["ports"] = {
            port: {"link": info["link"], "speed": info["speed"], "duplex": info["duplex"]}
            for port, info in sorted(status.items(), key=lambda item: _port_key(item[0]))
        }
    if (text := reads.get(SHOW_COUNTERS)) is not None:
        counters, notes = tables.parse_interface_counters(text)
        warnings += notes
        data["ports_with_errors"] = {
            port: errs
            for port, values in sorted(counters.items(), key=lambda item: _port_key(item[0]))
            if (errs := tables.error_counters(values))
        }
    if (text := reads.get(SHOW_LOGGING)) is not None:
        data["log_entries"] = tables.parse_log_entries(text, log_entries)
    environment = {
        name: tables.parse_environment(text)
        for name, command in ENVIRONMENT_SHOWS.items()
        if (text := reads.get(command)) is not None
    }
    if environment:
        data["environment"] = environment
    data["parse_warnings"] = warnings
    return _respond(tool, params, reads, data, include_raw=include_raw)


def _port_key(port: str) -> tuple[int, int]:
    slot, _, number = port.partition("/")
    try:
        return int(slot), int(number)
    except ValueError:
        return (999, 999)


# ------------------------------------------------------------- port_status


def port_status(include_raw: bool = False) -> str:
    """Per port as JSON: link, speed, duplex, description, VLANs, PoE
    (W/class/status) and LLDP neighbor. One session, read-only."""
    tool = "port_status"
    params = {"include_raw": include_raw}
    if (refusal := _guard(tool, params)) is not None:
        return refusal
    try:
        _check_bool(include_raw, "include_raw")
    except ValidationError as exc:
        return fail(tool, params, f"Rejected: {exc}", allowed=False)
    reads = _read_bundle([SHOW_STATUS, SHOW_DESCRIPTION, SHOW_VLAN, SHOW_POWER_INLINE, SHOW_LLDP])
    warnings: list[str] = []
    ports: dict[str, dict[str, Any]] = {}

    def entry(port: str) -> dict[str, Any]:
        return ports.setdefault(port, {"port": port})

    if (text := reads.get(SHOW_STATUS)) is not None:
        status, notes = tables.parse_interfaces_status(text)
        warnings += notes
        for port, info in status.items():
            entry(port).update(link=info["link"], speed=info["speed"], duplex=info["duplex"])
    if (text := reads.get(SHOW_DESCRIPTION)) is not None:
        for port, description in tables.parse_interface_descriptions(text).items():
            entry(port)["description"] = description
    if (text := reads.get(SHOW_VLAN)) is not None:
        membership, notes = tables.parse_vlan_membership(text)
        warnings += notes
        for port, vlans in membership.items():
            entry(port)["vlans"] = vlans
    if (text := reads.get(SHOW_POWER_INLINE)) is not None:
        poe, notes = tables.parse_power_inline(text)
        warnings += notes
        for port, info in poe.items():
            entry(port)["poe"] = {
                "power_w": info["power_w"], "class": info["class"],
                "status": info["status"], "admin": info["admin"],
            }
    if (text := reads.get(SHOW_LLDP)) is not None:
        neighbors, notes = tables.parse_lldp_neighbors(text)
        warnings += notes
        for neighbor in neighbors:
            entry(neighbor["local_port"]).setdefault("lldp", []).append(
                {"device_id": neighbor["device_id"], "port_id": neighbor["port_id"]}
            )
    data = {
        "ports": [ports[p] for p in sorted(ports, key=_port_key)],
        "parse_warnings": warnings,
    }
    return _respond(tool, params, reads, data, include_raw=include_raw)


# ----------------------------------------------------------- counters


def _validate_optional_port(port: str | None) -> None:
    if port is not None:
        validate_port(port)


def port_counters(port: str | None = None, include_raw: bool = False) -> str:
    """Interface counters as JSON for all ports or one port."""
    tool = "port_counters"
    params = {"port": port, "include_raw": include_raw}
    if (refusal := _guard(tool, params)) is not None:
        return refusal
    try:
        _validate_optional_port(port)
        _check_bool(include_raw, "include_raw")
    except ValidationError as exc:
        return fail(tool, params, f"Rejected: {exc}", allowed=False)
    reads = _read_bundle([SHOW_COUNTERS])
    data: dict[str, Any] = {"parse_warnings": []}
    if (text := reads.get(SHOW_COUNTERS)) is not None:
        counters, data["parse_warnings"] = tables.parse_interface_counters(text)
        if port is not None:
            counters = {port: counters[port]} if port in counters else {}
            if not counters:
                data["parse_warnings"].append(f"{port}: no counter row recognised")
        data["counters"] = counters
    return _respond(tool, params, reads, data, include_raw=include_raw)


def counters_delta(port: str | None = None) -> str:
    """Difference of the interface counters since the last counters_delta call
    (state kept in SWITCH_STATE_DIR). The first call stores the baseline.
    Detects new errors without clear counters."""
    tool = "counters_delta"
    params = {"port": port}
    if (refusal := _guard(tool, params)) is not None:
        return refusal
    try:
        _validate_optional_port(port)
    except ValidationError as exc:
        return fail(tool, params, f"Rejected: {exc}", allowed=False)
    reads = _read_bundle([SHOW_COUNTERS])
    text = reads.get(SHOW_COUNTERS)
    if text is None:
        return _respond(tool, params, reads, {}, include_raw=False)
    current, warnings = tables.parse_interface_counters(text)
    now = datetime.now(UTC).isoformat()
    previous = configstore.read_state(COUNTERS_STATE)
    data: dict[str, Any] = {"time": now, "parse_warnings": warnings}
    if current:
        try:
            configstore.write_state(COUNTERS_STATE, {"time": now, "counters": current})
        except OSError as exc:
            warnings.append(f"State not stored ({configstore.state_dir()}): {exc}")
    if not previous or not isinstance(previous.get("counters"), dict):
        data["baseline"] = True
        data["note"] = "Baseline stored; call again later for the difference."
        return _respond(tool, params, reads, data, include_raw=False)
    data["since"] = previous.get("time")
    deltas: dict[str, dict[str, int | float]] = {}
    reset_ports: list[str] = []
    for name, values in current.items():
        if port is not None and name != port:
            continue
        old = previous["counters"].get(name) or {}
        changed: dict[str, int | float] = {}
        for key, value in values.items():
            before = old.get(key)
            if isinstance(value, (int, float)) and isinstance(before, (int, float)):
                diff = value - before
                if diff < 0:
                    reset_ports.append(name)
                    changed = {}
                    break
                if diff:
                    changed[key] = diff
        if changed:
            deltas[name] = changed
    data["deltas"] = deltas
    data["new_errors"] = {
        name: errs for name, values in deltas.items() if (errs := tables.error_counters(values))
    }
    if reset_ports:
        data["counters_reset"] = sorted(set(reset_ports), key=_port_key)
    return _respond(tool, params, reads, data, include_raw=False)


# ------------------------------------------------------------ mac_table


def mac_table(port: str | None = None, mac: str | None = None, include_raw: bool = False) -> str:
    """MAC address table as JSON (show mac-address-table and its count),
    optionally filtered by port or MAC address."""
    tool = "mac_table"
    params = {"port": port, "mac": mac, "include_raw": include_raw}
    if (refusal := _guard(tool, params)) is not None:
        return refusal
    try:
        _validate_optional_port(port)
        wanted = None
        if mac is not None:
            wanted = tables.normalize_mac(mac) if isinstance(mac, str) else None
            if wanted is None:
                raise ValidationError(f"Invalid MAC address {mac!r}.")
        _check_bool(include_raw, "include_raw")
    except ValidationError as exc:
        return fail(tool, params, f"Rejected: {exc}", allowed=False)
    reads = _read_bundle([SHOW_MAC, SHOW_MAC_COUNT])
    data: dict[str, Any] = {"parse_warnings": []}
    if (text := reads.get(SHOW_MAC)) is not None:
        entries, total, data["parse_warnings"] = tables.parse_mac_table(text)
        if port is not None:
            entries = [item for item in entries if item["port"] == port]
        if wanted is not None:
            entries = [item for item in entries if item["mac"] == wanted]
        data["entries"] = entries
        data["matched"] = len(entries)
        data["total_reported"] = total
    if (text := reads.get(SHOW_MAC_COUNT)) is not None:
        data["count"] = tables.parse_mac_count(text)
        if (note := _mac_count_note(data.get("total_reported"), data["count"])) is not None:
            data["count_note"] = note
    return _respond(tool, params, reads, data, include_raw=include_raw)


def _mac_count_note(total: int | None, counts: dict[str, int]) -> str | None:
    """Explain a gap between the listed entries and the device's count.

    Live check 0.3.0: the table listed 54 entries (its own footer said 54)
    while 'show mac-address-table count' reported 85 dynamic unicast
    addresses. The listing was complete (footer present), so the device
    counts differently (e.g. aged or internal entries); the tool reports
    both instead of guessing."""
    dynamic = [value for label, value in counts.items() if "dynamic" in label.lower()]
    if total is None or not dynamic or max(dynamic) == total:
        return None
    return (
        f"show mac-address-table lists {total} entries, show mac-address-table "
        f"count reports {max(dynamic)} dynamic addresses. The listing ended with "
        "the device's own total line, so this is the device's counting, not "
        "missing pages."
    )


def lldp_neighbors(include_raw: bool = False) -> str:
    """LLDP neighbors as JSON (local port, device id, port id, capability)."""
    tool = "lldp_neighbors"
    params = {"include_raw": include_raw}
    if (refusal := _guard(tool, params)) is not None:
        return refusal
    reads = _read_bundle([SHOW_LLDP])
    data: dict[str, Any] = {"parse_warnings": []}
    if (text := reads.get(SHOW_LLDP)) is not None:
        data["neighbors"], data["parse_warnings"] = tables.parse_lldp_neighbors(text)
    return _respond(tool, params, reads, data, include_raw=include_raw is True)


def poe_status(include_raw: bool = False) -> str:
    """PoE as JSON: budget, consumption and per-port admin/status/W/class."""
    tool = "poe_status"
    params = {"include_raw": include_raw}
    if (refusal := _guard(tool, params)) is not None:
        return refusal
    reads = _read_bundle([SHOW_POWER_DETAIL, SHOW_POWER_INLINE])
    data: dict[str, Any] = {"parse_warnings": []}
    if (text := reads.get(SHOW_POWER_DETAIL)) is not None:
        detail = tables.parse_power_detail(text)
        data["budget_w"] = detail["budget_w"]
        data["consumed_w"] = detail["consumed_w"]
    if (text := reads.get(SHOW_POWER_INLINE)) is not None:
        ports, data["parse_warnings"] = tables.parse_power_inline(text)
        data["ports"] = dict(sorted(ports.items(), key=lambda item: _port_key(item[0])))
    return _respond(tool, params, reads, data, include_raw=include_raw is True)


# ------------------------------------------------------------- config


def _config_reads(sources: list[str], *, with_system: bool = False) -> tuple[dict[str, str], str | None]:
    """Read the masked configs (and optionally show system information) in
    one session without a session log."""

    def _run(conn: Any) -> tuple[dict[str, str], str | None]:
        configs = {source: read_config(conn, source) for source in sources}
        system = None
        if with_system:
            system = send_paged_redacted(conn, SHOW_SYSTEM)
        return configs, system

    return run_in_session(_run, enable_session_log=False)


def _source(source: str) -> str:
    return configstore.validate_source(source)


def config_read(source: str = "running") -> str:
    """Return the masked running-config ('show current running-config';
    secrets replaced by [REDACTED] / [REDACTED-LINE]). source='startup'
    answers 'Not available': the LGS CLI cannot show the startup-config.
    The show tool keeps both denied."""
    tool = "config_read"
    params = {"source": source}
    try:
        source = _source(source)
        configs, _ = _config_reads([source])
    except ValidationError as exc:
        return fail(tool, params, f"Rejected: {exc}", allowed=False)
    except ConfigUnavailableError as exc:
        return fail(tool, params, f"Not available: {exc}", allowed=True)
    except SwitchConnectionError as exc:
        return fail(tool, params, f"Error: {exc}", allowed=True)
    text = configs[source]
    data = {
        "source": source,
        "sha256": configstore.sha256_text(text),
        "lines": len(text.splitlines()),
        "config": text,
    }
    return ok(tool, params, to_json(data))


def config_backup(source: str = "running", tag: str | None = None) -> str:
    """Store the masked running-config under SWITCH_BACKUP_DIR as
    YYYY-MM-DD_HHMM_running[_tag].cfg; returns path, SHA256 and the diff
    to the previous running backup. source='startup' is not available on
    this device."""
    tool = "config_backup"
    params = {"source": source, "tag": tag}
    try:
        source = _source(source)
        if tag is not None and (not isinstance(tag, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,24}", tag)):
            raise ValidationError("tag must be 1..24 characters from [A-Za-z0-9-].")
        configs, _ = _config_reads([source])
        stored = configstore.store_backup(configs[source], source, tag=tag)
    except ValidationError as exc:
        return fail(tool, params, f"Rejected: {exc}", allowed=False)
    except ConfigUnavailableError as exc:
        return fail(tool, params, f"Not available: {exc}", allowed=True)
    except SwitchConnectionError as exc:
        return fail(tool, params, f"Error: {exc}", allowed=True)
    except OSError as exc:
        return fail(tool, params, f"Error: backup not written: {exc}", allowed=True)
    return ok(tool, params, to_json(stored))


SAVED_TAG = "pre-save"


def last_saved_copy() -> tuple[str | None, str | None]:
    """(path, masked text) of the newest running-config copy stored by
    save_config (tag pre-save), or (None, None)."""
    path = configstore.latest_backup("running", tag=SAVED_TAG)
    if path is None:
        return None, None
    try:
        return str(path), path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return str(path), None


def config_diff() -> str:
    """Unsaved changes, as far as this device allows: the startup-config
    cannot be read, so the masked running-config is diffed against the copy
    save_config stored at the last save through this server (tag pre-save
    in SWITCH_BACKUP_DIR). Also returns the Config Save Status from show
    system information. Saves done outside this server are not seen."""
    tool = "config_diff"
    params: dict[str, Any] = {}
    try:
        configs, system = _config_reads(["running"], with_system=True)
    except (ValidationError, SwitchConnectionError) as exc:
        return fail(tool, params, f"Error: {exc}", allowed=True)
    baseline_path, baseline = last_saved_copy()
    data: dict[str, Any] = {
        "startup_config": "not readable on this device",
        "baseline": baseline_path,
        "config_save_status": tables.parse_system_information(system or "")["config_save_status"],
    }
    if baseline is None:
        data["unsaved_changes"] = None
        data["diff"] = None
        data["note"] = (
            "No running-config copy from a save_config call yet; only the "
            "Config Save Status is available. The next save_config "
            "(dry_run=false) stores the baseline."
        )
    else:
        diff = configstore.unified_diff(
            baseline, configs["running"], before_label="last save (pre-save copy)",
            after_label="running-config",
        )
        data["unsaved_changes"] = bool(diff)
        data["diff"] = diff
        data["note"] = (
            "Baseline is the running-config stored by the last save_config "
            "through this server; saves made elsewhere are not seen."
        )
    return ok(tool, params, to_json(data))


# ------------------------------------------------------------ audit_tail


UNFINISHED = (
    "unfinished: no result recorded (hub timeout such as MCP -32001, "
    "cancelled call, server restart, or still running)"
)


def audit_tail(n: int = 50) -> str:
    """Last n (1..500) audit log entries (JSON lines), redacted again on read.
    A call that has a start record but no result (hub timeout, restart)
    is listed with result 'unfinished'."""
    tool = "audit_tail"
    params = {"n": n}
    try:
        validate_int(n, name="n", low=1, high=AUDIT_TAIL_MAX)
    except ValidationError as exc:
        return fail(tool, params, f"Rejected: {exc}", allowed=False)
    path_str = audit_path()
    if not path_str:
        return fail(tool, params, "Error: SWITCH_AUDIT_LOG is not set.", allowed=True)
    path = Path(path_str).expanduser()
    if not path.is_file():
        return ok(tool, params, to_json({"path": str(path), "entries": []}))
    records: list[Any] = []
    # Start records are folded into their results, so read more lines.
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in deque(handle, maxlen=2 * n + 20):
            line = redact_secrets(line.strip())
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                record = {"unparsed": redact_device_text(line)}
            records.append(record)
    finished = {
        record.get("call_id")
        for record in records
        if isinstance(record, dict) and record.get("call_id") and record.get("phase") != "start"
    }
    entries: list[Any] = []
    for record in records:
        if isinstance(record, dict) and record.get("phase") == "start":
            if record.get("call_id") in finished:
                continue
            record = {
                "time": record.get("time"),
                "tool": record.get("tool"),
                "call_id": record.get("call_id"),
                "result": UNFINISHED,
            }
        entries.append(record)
    # Recorded like every call, after the entries above were read.
    return ok(tool, params, to_json({"path": str(path), "entries": entries[-n:]}))


# ------------------------------------------------------------- show_help

_HELP_PREFIX_RE = re.compile(r"^[a-z][a-z0-9-]*(?: [a-z0-9][a-z0-9-]*){0,4}$")


def show_help(prefix: str = "") -> str:
    """List CLI completions for 'show <prefix> ?' (to find undocumented show
    commands). The line is typed, '?' lists options, then Ctrl-U clears the
    line: nothing is executed. Only show prefixes ([a-z0-9-] words)."""
    tool = "show_help"
    params = {"prefix": prefix}
    try:
        if not isinstance(prefix, str):
            raise ValidationError("prefix must be a string.")
        normalized = " ".join(prefix.lower().split())
        if normalized.startswith("show"):
            normalized = normalized[4:].strip()
        if normalized and not _HELP_PREFIX_RE.fullmatch(normalized):
            raise ValidationError(
                "prefix must be up to 5 words from [a-z0-9-] (the part after 'show')."
            )
        line = f"show {normalized}".strip()
        text = run_in_session(lambda conn: send_help(conn, line), enable_session_log=False)
    except ValidationError as exc:
        return fail(tool, params, f"Rejected: {exc}", allowed=False)
    except SwitchConnectionError as exc:
        return fail(tool, params, f"Error: {exc}", allowed=True)
    data = {"typed": f"{line} ?", "help": redact_device_text(text, help_listing=True)}
    return ok(tool, params, to_json(data))


READ_TOOLS = (
    health_summary,
    port_status,
    port_counters,
    counters_delta,
    mac_table,
    lldp_neighbors,
    poe_status,
    config_read,
    config_backup,
    config_diff,
    audit_tail,
    show_help,
)

__all__ = [tool.__name__ for tool in READ_TOOLS] + ["READ_TOOLS"]
