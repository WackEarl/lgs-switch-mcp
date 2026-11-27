"""Allow/deny matrix for the example commands.yml and show rejection hints."""

from __future__ import annotations

import pytest
from netmiko_mcp.security import validate_command

from lgs_switch_mcp.toolkit import rejected_show_message, show_rejection_hint

# Commands that must stay allowed (read-only, complete LGS forms).
ALLOWED = [
    "show system information",
    "show clock",
    "show privilege",
    "show users",
    "show vlan",
    "show vlan 1",
    "show mac-address-table",
    "show power inline",
    "show power detail",
    "show interfaces status",
    "show interfaces counters",
    "show interfaces gigabitethernet 0/1",
    "show logging",
    "show spanning-tree",
    "show ip igmp snooping",
    "show radius server",
    "show snmp community",
    "show device temperature",
    "show system fan status",
    "show system utilization",
    "show monitor all",
    "show monitor session 1",
    "show priority-map in-priority-type vlanPri",
    "show priority-map in-priority-type ipDscp",
]

# Incomplete prefixes or missing allow entries: no allow match, not a deny hit
# (unless a more specific deny exists).
NO_ALLOW = [
    "show system",
    "show system fan",
    "show monitor",
    "show priority-map",
    "show priority-map in-priority-type",
    "show inventory",
    "show firmware",
]

# Deny wins: invalid on LGS, dangerous writes, or dumps reserved for other tools.
DENIED = [
    "show version",
    "sh version",
    "show ver",
    "show current running-config",
    "show running-config",
    "show startup-config",
    "show current",
    "show interface cable-diag gigabitethernet 0/1",
    "configure",
    "configure terminal",
    "conf t",
    "save",
    "write",
    "write memory",
    "reboot",
    "reload",
    "restore-defaults",
    "clear counters",
    "copy running-config startup-config",
    "erase startup-config",
    "delete flash:config",
    "set cli pagination off",
    "no snmp community public",
    "username admin password x",
    "ping 192.0.2.1",
    "traceroute 192.0.2.1",
    "lock",
    "debug all",
    "interface gigabitethernet 0/1",
    "shutdown",
    "power inline never",
    "description test",
    "end",
    "exit",
]


@pytest.mark.parametrize("command", ALLOWED)
def test_allow_matrix_permits_readonly_shows(
    command: str, reset_command_file: None
) -> None:
    verdict = validate_command(command)
    assert verdict.allowed is True, command
    assert verdict.reason == "ALLOWED"


@pytest.mark.parametrize("command", NO_ALLOW)
def test_allow_matrix_rejects_unknown_or_incomplete(
    command: str, reset_command_file: None
) -> None:
    verdict = validate_command(command)
    assert verdict.allowed is False, command
    assert verdict.reason == "NO_ALLOW_MATCH"


@pytest.mark.parametrize("command", DENIED)
def test_allow_matrix_blocks_denied_and_dangerous(
    command: str, reset_command_file: None
) -> None:
    verdict = validate_command(command)
    assert verdict.allowed is False, command
    assert verdict.reason == "DENY_MATCH"


def test_show_version_reason_and_hint(reset_command_file: None) -> None:
    verdict = validate_command("show version")
    assert verdict.allowed is False
    assert verdict.reason == "DENY_MATCH"
    message = rejected_show_message("show version", verdict.reason)
    assert message.startswith("Command rejected: DENY_MATCH.")
    assert "show system information" in message
    assert "not a valid command" in message


def test_show_system_reason_and_hint(reset_command_file: None) -> None:
    verdict = validate_command("show system")
    assert verdict.allowed is False
    assert verdict.reason == "NO_ALLOW_MATCH"
    message = rejected_show_message("show system", verdict.reason)
    assert message.startswith("Command rejected: NO_ALLOW_MATCH.")
    assert "show system information" in message
    assert "show system fan status" in message
    assert "show system utilization" in message


def test_show_tool_surfaces_hints(
    reset_command_file: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from lgs_switch_mcp.server import show

    monkeypatch.setattr("lgs_switch_mcp.server.run_show", lambda cmd: f"OK:{cmd}")
    version = show("show version")
    system = show("show system")
    allowed = show("show system information")
    assert version.startswith("Command rejected: DENY_MATCH.")
    assert "show system information" in version
    assert system.startswith("Command rejected: NO_ALLOW_MATCH.")
    assert "show system information" in system
    assert allowed == "OK:show system information"


def test_dangerous_rejections_have_no_alternative_hint(
    reset_command_file: None,
) -> None:
    for command in ("configure", "save", "reboot", "reload", "clear counters"):
        assert show_rejection_hint(command) is None
        message = rejected_show_message(command, "DENY_MATCH")
        assert message == "Command rejected: DENY_MATCH"


def test_config_dump_hint_points_at_config_read(reset_command_file: None) -> None:
    hint = show_rejection_hint("show current running-config")
    assert hint is not None
    assert "config_read" in hint
    assert "show system information" not in hint
