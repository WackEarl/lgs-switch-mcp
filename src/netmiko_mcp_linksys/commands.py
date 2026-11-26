"""CLI sequence builders for interface, PoE, and description changes."""

from __future__ import annotations

READBACK_INTERFACE = "show interfaces gigabitethernet {port}"
READBACK_POE = "show power inline gigabitethernet {port}"
READBACK_DESCRIPTION = "show interfaces description"


def build_admin_state_commands(port: str, enabled: bool) -> list[str]:
    return [
        f"interface gigabitethernet {port}",
        "no shutdown" if enabled else "shutdown",
    ]


def build_poe_commands(port: str, enabled: bool) -> list[str]:
    return [
        f"interface gigabitethernet {port}",
        "power inline enable" if enabled else "power inline disable",
    ]


def build_description_commands(port: str, text: str | None) -> list[str]:
    """Always quote the text: the LGS CLI takes only one word unquoted.

    validate_description() forbids quotes in the text, so quoting is safe.
    """
    if text is None:
        inner = "no description"
    else:
        inner = f'description "{text}"'
    return [
        f"interface gigabitethernet {port}",
        inner,
    ]


# ---------------------------------------------------------------- 0.3.0
# Syntax source: Linksys LGSXXX CLI User Manual (ISS CLI), see README.

READBACK_SYSTEM = "show system information"
READBACK_PORT_SECURITY = "show interface port-security gigabitethernet {port}"
READBACK_LOGGING_SERVER = "show logging-server"
READBACK_LOGGING = "show logging"
READBACK_HTTP = "show http server status"
READBACK_HTTPS = "show ip http secure server status"
READBACK_TELNET = "show telnet server"
READBACK_COUNTERS = "show interfaces counters"
CONFIG_SHOW = {"running": "show running-config", "startup": "show startup-config"}
CABLE_DIAG = "show interface cable-diag gigabitethernet {port}"


def build_port_security_commands(port: str, limit: int | None) -> list[str]:
    """``port-security <1-256>`` / ``no port-security`` (interface mode)."""
    inner = "no port-security" if limit is None else f"port-security {limit}"
    return [f"interface gigabitethernet {port}", inner]


def build_storm_control_commands(port: str, storm_type: str, level_pps: int | None) -> list[str]:
    """``storm-control {broadcast|unknown-multicast|dlf} level <pps>`` / ``no … level``."""
    if level_pps is None:
        inner = f"no storm-control {storm_type} level"
    else:
        inner = f"storm-control {storm_type} level {level_pps}"
    return [f"interface gigabitethernet {port}", inner]


def build_rate_limit_commands(port: str, direction: str, kbps: int | None) -> list[str]:
    """``rate-limit {input|output} <kbps>`` / ``no rate-limit {input|output}``."""
    inner = f"no rate-limit {direction}" if kbps is None else f"rate-limit {direction} {kbps}"
    return [f"interface gigabitethernet {port}", inner]


def build_poe_cycle_commands(port: str) -> tuple[list[str], list[str]]:
    return build_poe_commands(port, False), build_poe_commands(port, True)


def build_syslog_commands(
    server_ip: str, port: int, facility: str, severity: str, enabled: bool
) -> list[str]:
    """Global config. The ``no`` form repeats the documented entry arguments
    (the manual only says "the no form deletes an entry"; live check)."""
    entry = f"logging-server facility {facility} severity {severity} ipv4 {server_ip} port {port}"
    if not enabled:
        return [f"no {entry}"]
    return [entry, "logging-service enable", f"logging severity {severity}"]


def _quoted(text: str) -> str:
    """Quote values with spaces (as for descriptions); inputs never hold quotes."""
    return f'"{text}"' if " " in text else text


def build_identity_commands(
    location: str | None, contact: str | None, name: str | None = None
) -> list[str]:
    """``system location``/``system contact``; ``set switch-name`` last,
    because it changes the CLI prompt."""
    commands = []
    if location is not None:
        commands.append(f"system location {_quoted(location)}")
    if contact is not None:
        commands.append(f"system contact {_quoted(contact)}")
    if name is not None:
        commands.append(f"set switch-name {name}")
    return commands


def build_clear_counters_command(port: str | None) -> str:
    """Privileged exec, not config mode."""
    return "clear counters" if port is None else f"clear counters gigabitethernet {port}"


HTTP_ENABLE = "set ip http enable"
HTTP_DISABLE = "set ip http disable"
HTTPS_ENABLE = "ip http secure server"
HTTPS_DISABLE = "no ip http secure server"
TELNET_DISABLE = "no ip telnet service"
