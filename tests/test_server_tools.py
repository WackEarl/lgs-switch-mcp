from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from netmiko_mcp_linksys.audit import write_audit
from netmiko_mcp_linksys.server import (
    port_overview,
    port_set_description,
    save_config,
    show,
)
from netmiko_mcp_linksys.writetools import poe_disable, port_disable
from tests.fakes import FakeSwitch, install


def test_port_disable_rejects_protected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_PROTECTED_PORTS", "0/24")
    with patch("netmiko_mcp_linksys.writes.run_in_session") as run:
        result = port_disable("0/24", dry_run=False)
    run.assert_not_called()
    assert result.startswith("Rejected:")
    assert "protected port" in result


def test_poe_disable_rejects_protected_and_non_poe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_PROTECTED_PORTS", "0/8")
    with patch("netmiko_mcp_linksys.writes.run_in_session") as run:
        protected = poe_disable("0/8", dry_run=False)
        uplink = poe_disable("0/28", dry_run=False)
    run.assert_not_called()
    assert "protected port" in protected
    assert "PoE is only supported" in uplink


def test_port_disable_sends_builder_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_PROTECTED_PORTS", "0/24")
    from netmiko_mcp_linksys.commands import READBACK_INTERFACE

    readback = READBACK_INTERFACE.format(port="0/2")
    switch = install(monkeypatch, FakeSwitch({readback: ["Gi0/2 up", "Gi0/2 down"]}))
    result = json.loads(port_disable("0/2", dry_run=False))
    assert switch.config_sets == [["interface gigabitethernet 0/2", "shutdown"]]
    assert switch.config_kwargs[0]["error_pattern"] == "%"
    assert result["before"][readback] == "Gi0/2 up"
    assert result["after"][readback] == "Gi0/2 down"
    assert "-Gi0/2 up" in result["diff"][readback]
    assert "+Gi0/2 down" in result["diff"][readback]


def test_description_rejects_special_chars() -> None:
    with patch("netmiko_mcp_linksys.writes.run_in_session") as run:
        result = port_set_description("0/1", "bad|text", dry_run=False)
    run.assert_not_called()
    assert result.startswith("Rejected:")


def test_description_none_clears(monkeypatch: pytest.MonkeyPatch) -> None:
    switch = install(monkeypatch, FakeSwitch({"show interfaces description": "cleared"}))
    result = json.loads(port_set_description("0/1", None, dry_run=False))
    assert "could not verify (port row not found)" in result["readback_note"]
    assert switch.config_sets == [["interface gigabitethernet 0/1", "no description"]]


def test_description_allowed_on_protected_and_caution_ports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SWITCH_PROTECTED_PORTS", "0/24")
    monkeypatch.setenv("SWITCH_CAUTION_PORTS", "0/15")
    switch = install(monkeypatch, FakeSwitch({"show interfaces description": "x"}))
    for port in ("0/24", "0/15"):
        assert json.loads(port_set_description(port, "Uplink", dry_run=False))["sent"]
    assert len(switch.config_sets) == 2


def test_description_dry_run_is_default(monkeypatch: pytest.MonkeyPatch) -> None:
    switch = install(monkeypatch, FakeSwitch({"show interfaces description": "x"}))
    result = json.loads(port_set_description("0/1", "Desk"))
    assert result["dry_run"] is True and result["sent"] is False
    assert result["commands"] == ["interface gigabitethernet 0/1", 'description "Desk"']
    assert switch.config_sets == []


def test_save_config_dry_run_default_saves_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    switch = install(
        monkeypatch,
        FakeSwitch(
            {
                "show startup-config": "!\nsystem location A\nend\n",
                "show running-config": "!\nsystem location B\nend\n",
                "show system information": "Config Save Status : Not Saved\n",
            }
        ),
    )
    saved: list[object] = []
    monkeypatch.setattr("netmiko_mcp_linksys.server.save_in_session", saved.append)
    result = json.loads(save_config())
    assert saved == []
    assert result["sent"] is False
    assert "-system location A" in result["diff_startup_to_running"]
    assert "+system location B" in result["diff_startup_to_running"]
    assert result["config_save_status"] == "Not Saved"
    assert switch.config_sets == []


def test_save_config_backs_up_startup_and_diffs(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SWITCH_PRE_WRITE_SNAPSHOT", "required")
    install(
        monkeypatch,
        FakeSwitch(
            {
                "show startup-config": ["!\nsystem location A\nend\n", "!\nsystem location B\nend\n"],
                "show running-config": "!\nsystem location B\nend\n",
                "show system information": "Config Save Status : Saved\n",
            }
        ),
    )
    monkeypatch.setattr("netmiko_mcp_linksys.server.save_in_session", lambda _c: "Saved")
    result = json.loads(save_config(dry_run=False))
    backup = result["backup"]
    assert backup["path"].endswith("_startup_pre-save.cfg")
    assert (tmp_path / "backups").is_dir()
    assert "system location A" in open(backup["path"], encoding="utf-8").read()
    assert "+system location B" in result["diff_startup_old_to_new"]
    assert result["config_save_status"] == "Saved"


def test_save_config_refuses_without_backup_when_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SWITCH_PRE_WRITE_SNAPSHOT", "required")
    install(monkeypatch, FakeSwitch({}))
    saved: list[object] = []
    monkeypatch.setattr("netmiko_mcp_linksys.server.save_in_session", saved.append)
    result = save_config(dry_run=False)
    assert result.startswith("Error: Backup of the current startup-config failed")
    assert saved == []


def test_show_missing_command_file(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NETMIKO_MCP_COMMAND_FILE", raising=False)
    result = show("show system information")
    assert "NETMIKO_MCP_COMMAND_FILE" in result


def test_audit_log_written(audit_log, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_PROTECTED_PORTS", "0/24")
    port_disable("0/24", dry_run=False)
    lines = [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()]
    assert lines[-1]["tool"] == "port_disable"
    assert lines[-1]["allowed"] is False
    assert lines[-1]["params"] == {
        "port": "0/24", "confirm_caution_port": False, "dry_run": False,
    }
    assert "dummy-password-not-real" not in audit_log.read_text(encoding="utf-8")
    assert (audit_log.stat().st_mode & 0o777) == 0o600


def test_tools_registered() -> None:
    from netmiko_mcp_linksys.server import mcp

    names = {tool.name for tool in mcp._tool_manager.list_tools()}
    assert names == {
        "show",
        "port_overview",
        "port_set_description",
        "save_config",
        "snmp_view_create",
        "snmp_write_view_create",
        "snmp_community_create",
        "snmp_community_remove",
        "snmp_user_remove",
        # 0.3.0 read tools
        "health_summary",
        "port_status",
        "port_counters",
        "counters_delta",
        "mac_table",
        "lldp_neighbors",
        "poe_status",
        "config_read",
        "config_backup",
        "config_diff",
        "audit_tail",
        "show_help",
        # 0.3.0 write tools (port_set_admin_state / poe_set were split)
        "port_enable",
        "port_disable",
        "poe_enable",
        "poe_disable",
        "poe_cycle",
        "port_security_set",
        "storm_control_set",
        "rate_limit_set",
        "cable_diag",
        "syslog_set",
        "mgmt_services_set",
        "clear_counters",
        "system_identity_set",
    }


def test_disable_fails_closed_when_protected_ports_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SWITCH_PROTECTED_PORTS", raising=False)
    with patch("netmiko_mcp_linksys.writes.run_in_session") as run:
        admin = port_disable("0/1", dry_run=False)
        poe = poe_disable("0/1", dry_run=False)
    run.assert_not_called()
    assert admin.startswith("Rejected:")
    assert "fail-closed" in admin
    assert poe.startswith("Rejected:")

def test_enable_allowed_when_protected_ports_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SWITCH_PROTECTED_PORTS", raising=False)
    from netmiko_mcp_linksys.writetools import poe_enable, port_enable

    switch = install(monkeypatch, FakeSwitch({}))
    assert json.loads(port_enable("0/1", dry_run=False))["sent"] is True
    assert json.loads(poe_enable("0/1", dry_run=False))["sent"] is True
    assert switch.config_sets == [
        ["interface gigabitethernet 0/1", "no shutdown"],
        ["interface gigabitethernet 0/1", "power inline enable"],
    ]


def test_port_overview_is_read_only(reset_command_file: None, monkeypatch: pytest.MonkeyPatch) -> None:
    from netmiko_mcp_linksys.server import PORT_OVERVIEW_COMMANDS

    seen: list[list[str]] = []

    def fake_sequence(commands: list[str]) -> list[tuple[str, str | None, str | None]]:
        seen.append(list(commands))
        return [(command, f"OUT:{command}", None) for command in commands]

    with (
        patch("netmiko_mcp_linksys.server.run_show", create=True) as run_show,
        patch(
            "netmiko_mcp_linksys.server.run_show_sequence", side_effect=fake_sequence
        ) as run_seq,
        patch("netmiko_mcp_linksys.writes.run_in_session") as run_cfg,
        patch("netmiko_mcp_linksys.server.save_in_session") as run_save,
        patch("netmiko_mcp_linksys.server.run_config_set", create=True) as run_set,
    ):
        result = port_overview()
    assert seen == [list(PORT_OVERVIEW_COMMANDS)]
    run_seq.assert_called_once()
    run_show.assert_not_called()
    run_cfg.assert_not_called()
    run_save.assert_not_called()
    run_set.assert_not_called()
    for command in PORT_OVERVIEW_COMMANDS:
        assert command in result
        assert f"OUT:{command}" in result
    assert not result.startswith("Error:")


def test_port_overview_opens_one_session(
    reset_command_file: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for #5: one SSH session for all four show commands."""
    from netmiko_mcp_linksys.server import PORT_OVERVIEW_COMMANDS

    monkeypatch.setenv("SWITCH_PAGING_OFF", "0")
    conn = MagicMock()
    with (
        patch("netmiko_mcp_linksys.connection.ConnectHandler", return_value=conn) as ch,
        patch(
            "netmiko_mcp_linksys.connection.send_paged",
            side_effect=lambda _conn, command: f"OUT:{command}",
        ) as paged,
    ):
        result = port_overview()
    ch.assert_called_once()
    conn.disconnect.assert_called_once()
    conn.send_config_set.assert_not_called()
    assert [c.args for c in paged.call_args_list] == [
        (conn, command) for command in PORT_OVERVIEW_COMMANDS
    ]
    sections = [f"=== {command} ===\nOUT:{command}" for command in PORT_OVERVIEW_COMMANDS]
    assert result == "\n\n".join(sections)


def test_port_overview_stops_after_failed_command(
    reset_command_file: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    from netmiko_mcp_linksys.connection import SEQUENCE_SKIPPED
    from netmiko_mcp_linksys.connection import SwitchConnectionError
    from netmiko_mcp_linksys.server import PORT_OVERVIEW_COMMANDS

    password = os.environ["SWITCH_PASSWORD"]
    monkeypatch.setenv("SWITCH_PAGING_OFF", "0")
    conn = MagicMock()
    first, second, third, fourth = PORT_OVERVIEW_COMMANDS
    with (
        patch("netmiko_mcp_linksys.connection.ConnectHandler", return_value=conn) as ch,
        patch(
            "netmiko_mcp_linksys.connection.send_paged",
            side_effect=[
                "INFO",
                SwitchConnectionError(f"No prompt after {second!r} ({password})"),
            ],
        ) as paged,
    ):
        result = port_overview()
    ch.assert_called_once()
    assert paged.call_count == 2
    assert result.startswith(f"=== {first} ===\nINFO")
    assert "=== errors ===" in result
    assert f"{second}: No prompt after" in result
    assert f"{third}: {SEQUENCE_SKIPPED}" in result
    assert f"{fourth}: {SEQUENCE_SKIPPED}" in result
    assert password not in result


def test_port_overview_unexpected_error_is_redacted(
    reset_command_file: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    from netmiko_mcp_linksys.server import PORT_OVERVIEW_COMMANDS

    password = os.environ["SWITCH_PASSWORD"]
    monkeypatch.setenv("SWITCH_PAGING_OFF", "0")
    conn = MagicMock()
    with (
        patch("netmiko_mcp_linksys.connection.ConnectHandler", return_value=conn),
        patch(
            "netmiko_mcp_linksys.connection.send_paged",
            side_effect=OSError(f"socket closed {password}"),
        ) as paged,
    ):
        result = port_overview()
    paged.assert_called_once()
    assert result.startswith("Error: ")
    assert f"{PORT_OVERVIEW_COMMANDS[0]}: socket closed ***" in result
    assert password not in result


def test_port_overview_connect_failure_single_attempt(
    reset_command_file: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    from netmiko_mcp_linksys.server import PORT_OVERVIEW_COMMANDS

    password = os.environ["SWITCH_PASSWORD"]
    with patch(
        "netmiko_mcp_linksys.connection.ConnectHandler",
        side_effect=RuntimeError(f"auth failed for {password}"),
    ) as ch:
        result = port_overview()
    ch.assert_called_once()
    assert result.startswith("Error: ")
    for command in PORT_OVERVIEW_COMMANDS:
        assert f"{command}: auth failed for ***" in result
    assert password not in result


def test_port_overview_requires_command_file(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NETMIKO_MCP_COMMAND_FILE", raising=False)
    with patch("netmiko_mcp_linksys.server.run_show_sequence") as run:
        result = port_overview()
    run.assert_not_called()
    assert "NETMIKO_MCP_COMMAND_FILE" in result


def test_audit_log_redacts_password_in_params_and_result(
    audit_log, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    password = os.environ["SWITCH_PASSWORD"]
    write_audit(
        tool="show",
        params={"command": f"leaked {password}"},
        allowed=False,
        result=f"auth failed for {password}",
    )
    body = audit_log.read_text(encoding="utf-8")
    assert password not in body
    assert "***" in body
    record = json.loads(body.splitlines()[-1])
    assert record["params"]["command"] == "leaked ***"
    assert record["result"] == "auth failed for ***"
    assert (audit_log.stat().st_mode & 0o777) == 0o600
