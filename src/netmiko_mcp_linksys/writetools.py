"""0.3.0 write tools. Registered on the MCP server in ``server``.

All tools default to ``dry_run=True`` and go through ``writes.execute``.
Single ports only (no ``interface range``). Protected ports
(SWITCH_PROTECTED_PORTS) are refused by every port tool here except the
two enable tools; caution ports (SWITCH_CAUTION_PORTS) need
``confirm_caution_port=True``, which is recorded in the audit log.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

from netmiko_mcp_linksys import configstore, writes
from netmiko_mcp_linksys.commands import (
    CABLE_DIAG,
    HTTP_DISABLE,
    HTTP_ENABLE,
    HTTPS_DISABLE,
    HTTPS_ENABLE,
    READBACK_COUNTERS,
    READBACK_HTTP,
    READBACK_HTTPS,
    READBACK_INTERFACE,
    READBACK_LOGGING,
    READBACK_LOGGING_SERVER,
    READBACK_POE,
    READBACK_PORT_SECURITY,
    READBACK_SYSTEM,
    READBACK_TELNET,
    TELNET_DISABLE,
    build_admin_state_commands,
    build_clear_counters_command,
    build_identity_commands,
    build_poe_commands,
    build_port_security_commands,
    build_rate_limit_commands,
    build_storm_control_commands,
    build_syslog_commands,
)
from netmiko_mcp_linksys.connection import (
    CONFIG_ERROR_PATTERN,
    SwitchConnectionError,
    _send_config,
    run_in_session,
    send_paged,
    send_paged_redacted,
)
from netmiko_mcp_linksys.errors import wrap_transport_error
from netmiko_mcp_linksys.redaction import redact_device_text
from netmiko_mcp_linksys.toolkit import fail, ok
from netmiko_mcp_linksys.validation import (
    RATE_DIRECTIONS,
    STORM_TYPES,
    SYSLOG_FACILITIES,
    SYSLOG_SEVERITIES,
    ValidationError,
    redact_secrets,
    reject_if_protected,
    reject_protected_port,
    require_caution_confirmation,
    validate_choice,
    validate_identity_text,
    validate_int,
    validate_port,
    validate_switch_name,
    validate_syslog_target,
)

COUNTERS_STATE = "counters.json"
POE_CYCLE_MIN_SECONDS = 2
POE_CYCLE_MAX_SECONDS = 60


def _require_bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValidationError(f"{name} must be true or false.")
    return value


def _port_guard(
    port: str,
    *,
    action: str,
    confirm_caution_port: bool,
    poe: bool = False,
    protect: bool = True,
) -> list[str]:
    """Validate the port; refuse protected ports (when ``protect``) and
    unconfirmed caution ports. Returns warnings for the result."""
    validate_port(port, poe=poe)
    if protect:
        reject_protected_port(port, action=action)
    warnings = []
    if require_caution_confirmation(port, confirmed=confirm_caution_port, action=action):
        warnings.append(f"{port} is a caution port; confirmed with confirm_caution_port=true.")
    return warnings


def _run(tool: str, params: dict[str, Any], build: Any, *, dry_run: bool) -> str:
    """Common wrapper: validation errors are refusals (allowed=False)."""
    try:
        _require_bool(dry_run, "dry_run")
        plan = build()
        output = writes.execute(plan, dry_run=dry_run)
    except ValidationError as exc:
        return fail(tool, params, f"Rejected: {exc}", allowed=False)
    except SwitchConnectionError as exc:
        return fail(tool, params, f"Error: {exc}", allowed=True)
    return ok(tool, params, output, audit_result="dry run" if dry_run else "ok")


# --------------------------------------------------------------- port state


def port_enable(port: str, confirm_caution_port: bool = False, dry_run: bool = True) -> str:
    """Enable a switch port (no shutdown). Allowed on protected ports.
    dry_run=true (default) only shows commands and current state. Does not save."""
    params = {"port": port, "confirm_caution_port": confirm_caution_port, "dry_run": dry_run}

    def build() -> writes.WritePlan:
        warnings = _port_guard(
            port, action="port_enable", confirm_caution_port=confirm_caution_port, protect=False
        )
        return writes.WritePlan(
            tool="port_enable",
            stages=[writes.Stage(build_admin_state_commands(port, True))],
            readbacks=[READBACK_INTERFACE.format(port=port)],
            expected=f"{port} administratively up",
            warnings=warnings,
        )

    return _run("port_enable", params, build, dry_run=dry_run)


def port_disable(port: str, confirm_caution_port: bool = False, dry_run: bool = True) -> str:
    """Disable a switch port (shutdown). Protected ports are refused (fail-closed).
    dry_run=true (default) only shows commands and current state. Does not save."""
    params = {"port": port, "confirm_caution_port": confirm_caution_port, "dry_run": dry_run}

    def build() -> writes.WritePlan:
        warnings = _port_guard(
            port, action="port_disable", confirm_caution_port=confirm_caution_port, protect=False
        )
        reject_if_protected(port, disabling=True, action="port_disable")
        return writes.WritePlan(
            tool="port_disable",
            stages=[writes.Stage(build_admin_state_commands(port, False))],
            readbacks=[READBACK_INTERFACE.format(port=port)],
            expected=f"{port} administratively down",
            warnings=warnings,
        )

    return _run("port_disable", params, build, dry_run=dry_run)


def poe_enable(port: str, confirm_caution_port: bool = False, dry_run: bool = True) -> str:
    """Enable PoE on a copper port (0/1..0/24). Allowed on protected ports.
    dry_run=true (default) only shows commands and current state. Does not save."""
    params = {"port": port, "confirm_caution_port": confirm_caution_port, "dry_run": dry_run}

    def build() -> writes.WritePlan:
        warnings = _port_guard(
            port, action="poe_enable", confirm_caution_port=confirm_caution_port,
            poe=True, protect=False,
        )
        return writes.WritePlan(
            tool="poe_enable",
            stages=[writes.Stage(build_poe_commands(port, True))],
            readbacks=[READBACK_POE.format(port=port)],
            expected=f"PoE admin enabled on {port}",
            warnings=warnings,
        )

    return _run("poe_enable", params, build, dry_run=dry_run)


def poe_disable(port: str, confirm_caution_port: bool = False, dry_run: bool = True) -> str:
    """Disable PoE on a copper port. Protected ports are refused (fail-closed).
    dry_run=true (default) only shows commands and current state. Does not save."""
    params = {"port": port, "confirm_caution_port": confirm_caution_port, "dry_run": dry_run}

    def build() -> writes.WritePlan:
        warnings = _port_guard(
            port, action="poe_disable", confirm_caution_port=confirm_caution_port,
            poe=True, protect=False,
        )
        reject_if_protected(port, disabling=True, action="poe_disable")
        return writes.WritePlan(
            tool="poe_disable",
            stages=[writes.Stage(build_poe_commands(port, False))],
            readbacks=[READBACK_POE.format(port=port)],
            expected=f"PoE admin disabled on {port} (the powered device loses power)",
            warnings=warnings,
        )

    return _run("poe_disable", params, build, dry_run=dry_run)


# ----------------------------------------------------------- port features


def port_security_set(
    port: str,
    limit: int | None = None,
    confirm_caution_port: bool = False,
    dry_run: bool = True,
) -> str:
    """Set port security (max learned MACs 1..256) or turn it off (limit omitted).
    Protected ports are refused. dry_run=true by default. Does not save."""
    params = {
        "port": port, "limit": limit,
        "confirm_caution_port": confirm_caution_port, "dry_run": dry_run,
    }

    def build() -> writes.WritePlan:
        warnings = _port_guard(
            port, action="port_security_set", confirm_caution_port=confirm_caution_port
        )
        if limit is not None:
            validate_int(limit, name="limit", low=1, high=256)
            warnings.append(
                "Port security limits learned MACs; devices beyond the limit lose "
                "connectivity on this port."
            )
        return writes.WritePlan(
            tool="port_security_set",
            stages=[writes.Stage(build_port_security_commands(port, limit))],
            readbacks=[READBACK_PORT_SECURITY.format(port=port)],
            expected=(
                f"port security off on {port}" if limit is None
                else f"port security on {port}, max {limit} MAC addresses"
            ),
            warnings=warnings,
        )

    return _run("port_security_set", params, build, dry_run=dry_run)


def storm_control_set(
    port: str,
    storm_type: str,
    level_pps: int | None = None,
    confirm_caution_port: bool = False,
    dry_run: bool = True,
) -> str:
    """Set storm control (broadcast | unknown-multicast | dlf) in packets per
    second, or remove it (level_pps omitted). Read-back from running-config.
    Protected ports are refused. dry_run=true by default. Does not save."""
    params = {
        "port": port, "storm_type": storm_type, "level_pps": level_pps,
        "confirm_caution_port": confirm_caution_port, "dry_run": dry_run,
    }

    def build() -> writes.WritePlan:
        warnings = _port_guard(
            port, action="storm_control_set", confirm_caution_port=confirm_caution_port
        )
        validate_choice(storm_type, name="storm_type", choices=STORM_TYPES)
        if level_pps is not None:
            validate_int(level_pps, name="level_pps", low=1, high=262143)
            warnings.append(
                "The level range is not documented in the manual; the device "
                "rejects out-of-range values with '%'."
            )
        return writes.WritePlan(
            tool="storm_control_set",
            stages=[writes.Stage(build_storm_control_commands(port, storm_type, level_pps))],
            config_block_port=port,
            expected=(
                f"no {storm_type} storm control on {port}" if level_pps is None
                else f"{storm_type} storm control {level_pps} pps on {port}"
            ),
            warnings=warnings,
        )

    return _run("storm_control_set", params, build, dry_run=dry_run)


def rate_limit_set(
    port: str,
    direction: str,
    kbps: int | None = None,
    confirm_caution_port: bool = False,
    dry_run: bool = True,
) -> str:
    """Set an input or output rate limit in kbps (1..80000000), or remove it
    (kbps omitted). Protected ports are refused. dry_run=true by default."""
    params = {
        "port": port, "direction": direction, "kbps": kbps,
        "confirm_caution_port": confirm_caution_port, "dry_run": dry_run,
    }

    def build() -> writes.WritePlan:
        warnings = _port_guard(
            port, action="rate_limit_set", confirm_caution_port=confirm_caution_port
        )
        validate_choice(direction, name="direction", choices=RATE_DIRECTIONS)
        if kbps is not None:
            validate_int(kbps, name="kbps", low=1, high=80_000_000)
        return writes.WritePlan(
            tool="rate_limit_set",
            stages=[writes.Stage(build_rate_limit_commands(port, direction, kbps))],
            config_block_port=port,
            expected=(
                f"no {direction} rate limit on {port}" if kbps is None
                else f"{direction} rate limit {kbps} kbps on {port}"
            ),
            warnings=warnings,
        )

    return _run("rate_limit_set", params, build, dry_run=dry_run)


# ------------------------------------------------------------- poe_cycle


def _set_poe(conn: Any, port: str, enabled: bool) -> str:
    return _send_config(conn, build_poe_commands(port, enabled), error_pattern=CONFIG_ERROR_PATTERN)


def poe_cycle(
    port: str,
    off_seconds: int = 5,
    confirm_caution_port: bool = False,
    dry_run: bool = True,
) -> str:
    """Power-cycle the device on a PoE port: PoE off, wait off_seconds (2..60),
    PoE on. PoE is switched on again even if the wait or the session fails
    (finally, then one retry in a new session). Protected ports are refused
    hard. dry_run=true by default. Does not save."""
    tool = "poe_cycle"
    params = {
        "port": port, "off_seconds": off_seconds,
        "confirm_caution_port": confirm_caution_port, "dry_run": dry_run,
    }
    readback = READBACK_POE.format(port=port)
    try:
        _require_bool(dry_run, "dry_run")
        warnings = _port_guard(
            port, action=tool, confirm_caution_port=confirm_caution_port, poe=True
        )
        validate_int(off_seconds, name="off_seconds", low=POE_CYCLE_MIN_SECONDS,
                     high=POE_CYCLE_MAX_SECONDS)
        off_cmds = build_poe_commands(port, False)
        on_cmds = build_poe_commands(port, True)
        if dry_run:
            plan = writes.WritePlan(
                tool=tool,
                stages=[writes.Stage(off_cmds), writes.Stage(on_cmds)],
                readbacks=[readback],
                expected=f"PoE off for {off_seconds}s on {port}, then on again",
                warnings=warnings,
                snapshot=False,
            )
            return ok(tool, params, writes.execute(plan, dry_run=True), audit_result="dry run")

        state: dict[str, Any] = {"off_attempted": False, "off_sent": False, "on_sent": False}

        def _cycle(conn: Any) -> dict[str, Any]:
            before = send_paged_redacted(conn, readback)
            state["off_attempted"] = True
            try:
                _set_poe(conn, port, False)
                state["off_sent"] = True
                time.sleep(off_seconds)
            finally:
                # Always try to switch PoE back on in this session. A failure
                # here is retried in a new session below.
                try:
                    _set_poe(conn, port, True)
                    state["on_sent"] = True
                except Exception as exc:  # noqa: BLE001 - retried below
                    state["on_error"] = redact_secrets(str(exc))
            after = send_paged_redacted(conn, readback)
            return {"before": before, "after": after}

        error: BaseException | None = None
        data: dict[str, Any] = {}
        try:
            data = run_in_session(_cycle, enable_session_log=False)
        except (ValidationError, SwitchConnectionError) as exc:
            error = exc
        if state["off_attempted"] and not state["on_sent"]:
            # Retry once in a fresh session (the off command may have been
            # applied even if it reported an error). Never when the off
            # command was not attempted: PoE may be off on purpose.
            try:
                run_in_session(
                    lambda conn: _set_poe(conn, port, True),
                    enable_session_log=False,
                    bypass_cooldown=True,
                )
                state["on_sent"] = True
                state["on_retry"] = True
            except (ValidationError, SwitchConnectionError) as exc:
                state["on_retry_error"] = redact_secrets(str(exc))
        if state["off_attempted"] and not state["on_sent"]:
            return fail(
                tool,
                params,
                f"Error: PoE on {port} may be left DISABLED. Re-enabling failed "
                f"twice ({state.get('on_retry_error') or state.get('on_error')}). "
                f"Run poe_enable(port={port!r}, dry_run=false) now.",
                allowed=True,
            )
        if error is not None:
            suffix = (
                f" PoE on {port} was switched on again"
                + (" (retry in a new session)." if state.get("on_retry") else ".")
                if state["off_attempted"]
                else " Nothing was sent."
            )
            return fail(tool, params, f"Error: {error}{suffix}", allowed=True)
        result = {
            "tool": tool,
            "dry_run": False,
            "sent": True,
            "commands": off_cmds + on_cmds,
            "off_seconds": off_seconds,
            "before": data.get("before"),
            "after": data.get("after"),
            "warnings": warnings,
            "note": writes.NOT_SAVED,
        }
        return ok(tool, params, json.dumps(result, indent=2, ensure_ascii=False))
    except ValidationError as exc:
        return fail(tool, params, f"Rejected: {exc}", allowed=False)
    except SwitchConnectionError as exc:
        return fail(tool, params, f"Error: {exc}", allowed=True)


# ------------------------------------------------------------- cable_diag


def cable_diag(port: str, confirm_caution_port: bool = False, dry_run: bool = True) -> str:
    """Run the cable diagnostic (TDR) on one port. Active test: it can drop the
    link for a few seconds. Protected ports are refused. The command stays
    denied for the show tool and only runs here. dry_run=true by default."""
    tool = "cable_diag"
    params = {"port": port, "confirm_caution_port": confirm_caution_port, "dry_run": dry_run}
    command = CABLE_DIAG.format(port=port)
    warning = "Cable diagnostics can interrupt the link on this port for a few seconds."
    try:
        _require_bool(dry_run, "dry_run")
        warnings = _port_guard(port, action=tool, confirm_caution_port=confirm_caution_port)
        warnings.append(warning)
        if dry_run:
            result = {
                "tool": tool, "dry_run": True, "sent": False, "commands": [command],
                "warnings": warnings,
                "note": "Dry run: nothing was sent. Call again with dry_run=false to run the test.",
            }
            return ok(tool, params, json.dumps(result, indent=2), audit_result="dry run")

        def _diag(conn: Any) -> str:
            try:
                return redact_device_text(send_paged(conn, command))
            except SwitchConnectionError:
                raise
            except Exception as exc:  # noqa: BLE001
                raise wrap_transport_error(exc) from None

        output = run_in_session(_diag, enable_session_log=False)
        result = {
            "tool": tool, "dry_run": False, "sent": True, "commands": [command],
            "output": output, "warnings": warnings,
        }
        return ok(tool, params, json.dumps(result, indent=2, ensure_ascii=False))
    except ValidationError as exc:
        return fail(tool, params, f"Rejected: {exc}", allowed=False)
    except SwitchConnectionError as exc:
        return fail(tool, params, f"Error: {exc}", allowed=True)


# ---------------------------------------------------------------- syslog


def syslog_set(
    server_ip: str,
    port: int = 514,
    facility: str = "local0",
    severity: str = "informational",
    enabled: bool = True,
    dry_run: bool = True,
) -> str:
    """Add (enabled=true) or remove (enabled=false) a syslog server. The target
    must be listed in SWITCH_SYSLOG_ALLOWED. Severity uses the ISS keywords
    (emergencies, alerts, critical, errors, warnings, notification,
    informational, debugging). dry_run=true by default. Does not save."""
    params = {
        "server_ip": server_ip, "port": port, "facility": facility,
        "severity": severity, "enabled": enabled, "dry_run": dry_run,
    }

    def build() -> writes.WritePlan:
        validate_syslog_target(server_ip)
        validate_int(port, name="port", low=1, high=65535)
        validate_choice(facility, name="facility", choices=SYSLOG_FACILITIES)
        validate_choice(severity, name="severity", choices=SYSLOG_SEVERITIES)
        _require_bool(enabled, "enabled")
        warnings = []
        if not enabled:
            warnings.append(
                "The manual does not document the arguments of 'no logging-server'; "
                "the full entry is repeated (live check)."
            )
        return writes.WritePlan(
            tool="syslog_set",
            stages=[writes.Stage(build_syslog_commands(server_ip, port, facility, severity, enabled))],
            readbacks=[READBACK_LOGGING_SERVER, READBACK_LOGGING],
            expected=(
                f"syslog server {server_ip}:{port} ({facility}, {severity}) configured, "
                "logging enabled" if enabled
                else f"syslog server {server_ip}:{port} removed"
            ),
            warnings=warnings,
        )

    return _run("syslog_set", params, build, dry_run=dry_run)


# ---------------------------------------------------------- mgmt services

_STATUS_RE = re.compile(r"\b(enabled?|disabled?)\b", re.IGNORECASE)


def service_status(text: str) -> bool | None:
    """True/False when the read-back says only Enabled or only Disabled."""
    words = {
        "on" if match.group(1).lower().startswith("enabl") else "off"
        for match in _STATUS_RE.finditer(text)
    }
    if words == {"on"}:
        return True
    if words == {"off"}:
        return False
    return None


def _https_enabled(conn: Any) -> None:
    text = send_paged_redacted(conn, READBACK_HTTPS)
    if service_status(text) is not True:
        raise ValidationError(
            "HTTP stays enabled: HTTPS was not read back as Enabled "
            f"({READBACK_HTTPS!r} returned: {text.strip()[:200]!r})."
        )


def mgmt_services_set(
    http: bool | None = None,
    https: bool | None = None,
    disable_telnet: bool = False,
    dry_run: bool = True,
) -> str:
    """Harden management services: HTTP on/off, HTTPS on/off, Telnet off.
    SSH cannot be changed and Telnet cannot be enabled. HTTP is only disabled
    after HTTPS was read back as Enabled (in the same session, after an HTTPS
    enable from this call). dry_run=true by default. Does not save."""
    params = {"http": http, "https": https, "disable_telnet": disable_telnet, "dry_run": dry_run}

    def build() -> writes.WritePlan:
        if http is not None:
            _require_bool(http, "http")
        if https is not None:
            _require_bool(https, "https")
        _require_bool(disable_telnet, "disable_telnet")
        if http is None and https is None and not disable_telnet:
            raise ValidationError("Nothing to change: set http, https or disable_telnet.")
        if http is False and https is False:
            raise ValidationError(
                "Refusing to disable HTTP and HTTPS in one call; the web UI would be "
                "unreachable. Disable them one at a time."
            )
        stages: list[writes.Stage] = []
        warnings: list[str] = []
        expected: list[str] = []
        if https is True:
            stages.append(writes.Stage([HTTPS_ENABLE]))
            expected.append("HTTPS enabled")
            warnings.append(
                "The HTTPS server uses the switch certificate; the device may offer "
                "only weak ciphers. Check in a browser before disabling HTTP."
            )
        elif https is False:
            stages.append(writes.Stage([HTTPS_DISABLE]))
            expected.append("HTTPS disabled")
        if http is True:
            stages.append(writes.Stage([HTTP_ENABLE]))
            expected.append("HTTP enabled")
        elif http is False:
            stages.append(writes.Stage([HTTP_DISABLE], guard=_https_enabled))
            expected.append("HTTP disabled (only after HTTPS reads back Enabled)")
            warnings.append(
                "HTTP is only disabled if 'show ip http secure server status' reads "
                "back Enabled right before; otherwise the call stops there."
            )
        if disable_telnet:
            stages.append(writes.Stage([TELNET_DISABLE]))
            expected.append("Telnet disabled")
        return writes.WritePlan(
            tool="mgmt_services_set",
            stages=stages,
            readbacks=[READBACK_HTTP, READBACK_HTTPS, READBACK_TELNET],
            expected=", ".join(expected),
            warnings=warnings,
        )

    return _run("mgmt_services_set", params, build, dry_run=dry_run)


# --------------------------------------------------------- clear_counters


def clear_counters(port: str | None = None, confirm_caution_port: bool = False,
                   dry_run: bool = True) -> str:
    """Reset interface counters for one port or all ports (port omitted).
    Protected ports are refused when named. Also resets the counters_delta
    baseline. dry_run=true by default."""
    params = {"port": port, "confirm_caution_port": confirm_caution_port, "dry_run": dry_run}

    def build() -> writes.WritePlan:
        warnings: list[str] = []
        if port is not None:
            warnings = _port_guard(
                port, action="clear_counters", confirm_caution_port=confirm_caution_port
            )
        else:
            warnings.append("Clears the counters of all ports, protected ports included.")
        return writes.WritePlan(
            tool="clear_counters",
            stages=[writes.Stage([build_clear_counters_command(port)], exec_mode=True)],
            readbacks=[READBACK_COUNTERS],
            expected=f"counters of {port or 'all ports'} reset to 0",
            warnings=warnings,
            snapshot=False,
            after_write=lambda: configstore.clear_state(COUNTERS_STATE),
        )

    return _run("clear_counters", params, build, dry_run=dry_run)


# ------------------------------------------------------- system identity


def system_identity_set(
    location: str | None = None,
    contact: str | None = None,
    name: str | None = None,
    dry_run: bool = True,
) -> str:
    """Set system location, contact and/or switch name. Values: [A-Za-z0-9 ._-]
    (name without spaces, it becomes the CLI prompt). dry_run=true by default.
    Does not save."""
    params = {"location": location, "contact": contact, "name": name, "dry_run": dry_run}

    def build() -> writes.WritePlan:
        if location is None and contact is None and name is None:
            raise ValidationError("Nothing to change: set location, contact or name.")
        if location is not None:
            validate_identity_text(location, name="location")
        if contact is not None:
            validate_identity_text(contact, name="contact")
        warnings: list[str] = []
        if name is not None:
            validate_switch_name(name)
            warnings.append(
                "set switch-name changes the CLI prompt; it is sent last (live check)."
            )
        return writes.WritePlan(
            tool="system_identity_set",
            stages=[writes.Stage(build_identity_commands(location, contact, name))],
            readbacks=[READBACK_SYSTEM],
            refresh_prompt=name is not None,
            expected=", ".join(
                f"{label} = {value!r}"
                for label, value in (("location", location), ("contact", contact), ("name", name))
                if value is not None
            ),
            warnings=warnings,
        )

    return _run("system_identity_set", params, build, dry_run=dry_run)


WRITE_TOOLS = (
    port_enable,
    port_disable,
    poe_enable,
    poe_disable,
    poe_cycle,
    port_security_set,
    storm_control_set,
    rate_limit_set,
    cable_diag,
    syslog_set,
    mgmt_services_set,
    clear_counters,
    system_identity_set,
)

__all__ = [tool.__name__ for tool in WRITE_TOOLS] + ["WRITE_TOOLS", "service_status"]
