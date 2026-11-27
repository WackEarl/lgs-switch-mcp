"""0.3.1: fixes from the live check of 0.3.0 (fakes only, no device)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lgs_switch_mcp import readtools as r
from lgs_switch_mcp import tables
from lgs_switch_mcp.redaction import REDACTED_LINE, redact_device_text
from tests import samples_iss as s
from tests import samples_lgs_031 as live
from tests.fakes import FakeSwitch, install

# ------------------------------------------------------------- PoE parser


@pytest.mark.parametrize("text", [live.POWER_INLINE, live.POWER_INLINE_ONE_RULE])
def test_power_inline_bare_port_numbers_and_multiword_columns(text: str) -> None:
    ports, warnings = tables.parse_power_inline(text)
    assert warnings == []
    assert ports["0/1"]["power_w"] == 5.4
    assert ports["0/15"] == {
        "admin": "Enable",
        "status": "On",
        "power_w": 3.1,
        "max_power_w": 15.4,
        "class": "1",
        "auto_class": "Disabled",
        "limit_type": "User Defined",
        "device": None,
        "priority": "High",
    }


def test_power_inline_still_reads_gi_ports() -> None:
    ports, warnings = tables.parse_power_inline(s.POWER_INLINE)
    assert warnings == [] and ports["0/1"]["device"] == "AP-Floor1"
    assert ports["0/15"]["power_w"] == 3.1


def test_normalize_poe_port() -> None:
    assert tables.normalize_poe_port("7") == "0/7"
    assert tables.normalize_poe_port("Gi0/7") == "0/7"
    assert tables.normalize_poe_port("25") is None  # no PoE above 24
    assert tables.normalize_poe_port("0") is None


def test_poe_status_and_health_use_live_layout(
    monkeypatch: pytest.MonkeyPatch, reset_command_file: None
) -> None:
    install(
        monkeypatch,
        FakeSwitch({"show power detail": s.POWER_DETAIL_KV, "show power inline": live.POWER_INLINE}),
    )
    data = json.loads(r.poe_status())
    assert list(data["ports"]) == ["0/1", "0/2", "0/15", "0/24"]
    assert data["parse_warnings"] == []
    health = json.loads(r.health_summary())
    assert health["poe"]["ports_w"] == {"0/1": 5.4, "0/15": 3.1}
    assert "show power inline: no port rows recognised" not in health["parse_warnings"]


# ------------------------------------------------------------- VLAN parser


def test_vlan_key_value_blocks() -> None:
    membership, warnings = tables.parse_vlan_membership(live.VLAN_KV)
    assert warnings == []
    assert membership["0/1"] == [{"vlan": 1, "tagged": False}]
    assert membership["0/9"] == [{"vlan": 1, "tagged": False}]  # wrapped line
    assert membership["0/24"] == [{"vlan": 1, "tagged": True}, {"vlan": 20, "tagged": True}]
    assert membership["0/18"] == [{"vlan": 20, "tagged": False}]
    assert membership["po1"] == [{"vlan": 1, "tagged": False}]
    assert "0/11" not in membership


def test_vlan_unreadable_member_list_warns() -> None:
    membership, warnings = tables.parse_vlan_membership(live.VLAN_KV_UNREADABLE)
    assert membership == {}
    assert warnings == ["show vlan: member ports of VLAN 1 not recognised"]


def test_vlan_unknown_layout_warns() -> None:
    membership, warnings = tables.parse_vlan_membership("something\nwithout vlans\n")
    assert membership == {} and warnings == ["show vlan: no VLAN membership recognised"]


def test_vlan_old_table_layout_still_parsed() -> None:
    membership, warnings = tables.parse_vlan_membership(s.VLAN)
    assert membership and warnings == []


def test_port_status_vlans_and_warning(
    monkeypatch: pytest.MonkeyPatch, reset_command_file: None
) -> None:
    install(monkeypatch, FakeSwitch({"show interfaces status": s.STATUS, "show vlan": live.VLAN_KV}))
    data = json.loads(r.port_status())
    port1 = next(p for p in data["ports"] if p["port"] == "0/1")
    assert port1["vlans"] == [{"vlan": 1, "tagged": False}]
    install(
        monkeypatch,
        FakeSwitch({"show interfaces status": s.STATUS, "show vlan": live.VLAN_KV_UNREADABLE}),
    )
    data = json.loads(r.port_status())
    assert "show vlan: member ports of VLAN 1 not recognised" in data["parse_warnings"]


# --------------------------------------------------------------- allowlist


@pytest.mark.parametrize(
    ("command", "allowed"),
    [
        ("show monitor all", True),
        ("show monitor session 1", True),
        ("show monitor", False),
        ("show priority-map in-priority-type vlanPri", True),
        ("show priority-map in-priority-type ipDscp", True),
        ("show priority-map in-priority-type", False),
        ("show priority-map", False),
        ("show version", False),
        ("show device temperature", True),
        ("show system fan status", True),
        ("show system fan", False),
        ("show system utilization", True),
        ("show radius server", True),
        ("show current running-config", False),
        ("show running-config", False),
        ("show startup-config", False),
    ],
)
def test_example_allowlist(command: str, allowed: bool, reset_command_file: None) -> None:
    from netmiko_mcp.security import validate_command

    assert validate_command(command).allowed is allowed, command


# ------------------------------------------------------------ radius / help


def test_strict_redaction_never_empties_output() -> None:
    """show radius server came back empty live: strict redaction replaces
    lines but never drops them, so an empty answer was empty on the device."""
    text = "Server : 192.0.2.30\nShared Secret : s3cr3t-value\nweird table row 192.0.2.31 1812\n"
    out = redact_device_text(text, strict=True)
    assert len(out.splitlines()) == len(text.splitlines())
    assert "s3cr3t-value" not in out
    assert out.splitlines()[2] == REDACTED_LINE
    assert redact_device_text("", strict=True) == ""
    assert redact_device_text("\n", strict=True) == "\n"


def test_help_listing_keeps_snmp_entry() -> None:
    plain = redact_device_text(live.HELP_TOP)
    assert REDACTED_LINE in plain  # the 0.3.0 false positive
    out = redact_device_text(live.HELP_TOP, help_listing=True)
    assert REDACTED_LINE not in out
    assert "  snmp                  SNMP information" in out


@pytest.mark.parametrize(
    "line",
    [
        "  username              Show user password abc123",
        "  snmp                  community public-xyz",
        "  key                   " + "A1" * 30,
        "snmp community index c1 name secret-name security v2c",
    ],
)
def test_help_listing_stays_fail_closed(line: str) -> None:
    out = redact_device_text(line, help_listing=True)
    assert out != line


def test_show_help_tool_uses_help_redaction(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(r, "send_help", lambda _conn, _line: live.HELP_TOP)
    install(monkeypatch, FakeSwitch({}))
    data = json.loads(r.show_help(""))
    assert REDACTED_LINE not in data["help"]
    assert "snmp                  SNMP information" in data["help"]


# ------------------------------------------------------------------ audit


def _records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_audited_call_writes_start_and_result(audit_log: Path) -> None:
    from lgs_switch_mcp.audit import audited_call
    from lgs_switch_mcp.toolkit import ok

    def sample_tool(port: str = "0/1") -> str:
        return ok("sample_tool", {"port": port}, "done")

    assert audited_call(sample_tool)(port="0/3") == "done"
    start, result = _records(audit_log)
    assert start["phase"] == "start" and start["tool"] == "sample_tool"
    assert "params" not in start  # parameters only come from the tool itself
    assert result["call_id"] == start["call_id"]
    assert result["params"] == {"port": "0/3"} and result["result"] == "ok"
    assert isinstance(result["duration_ms"], int)


def test_audited_call_records_unexpected_exception(audit_log: Path) -> None:
    from lgs_switch_mcp.audit import audited_call

    def broken_tool() -> str:
        raise TimeoutError("read timed out")

    with pytest.raises(TimeoutError):
        audited_call(broken_tool)()
    start, result = _records(audit_log)
    assert result["call_id"] == start["call_id"]
    assert result["result"] == "Error: call ended without a result (TimeoutError)"


def test_audited_call_without_tool_record(audit_log: Path) -> None:
    from lgs_switch_mcp.audit import audited_call

    assert audited_call(lambda: "x")() == "x"
    start, result = _records(audit_log)
    assert result["call_id"] == start["call_id"] and result["result"] == "returned"


def test_audit_tail_reports_unfinished_calls(audit_log: Path) -> None:
    """A hub timeout (MCP -32001) or restart leaves a start record only."""
    lines = [
        {"time": "t1", "tool": "show", "phase": "start", "call_id": "aaa"},
        {"time": "t2", "tool": "show", "params": {}, "allowed": True, "result": "ok",
         "call_id": "aaa", "duration_ms": 5},
        {"time": "t3", "tool": "show", "phase": "start", "call_id": "bbb"},
    ]
    audit_log.write_text("".join(json.dumps(line) + "\n" for line in lines), encoding="utf-8")
    entries = json.loads(r.audit_tail(10))["entries"]
    assert [entry.get("call_id") for entry in entries] == ["aaa", "bbb"]
    assert entries[0]["result"] == "ok"
    assert entries[1]["result"].startswith("unfinished")


def test_registered_tools_are_audited(audit_log: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    from lgs_switch_mcp import server

    install(monkeypatch, FakeSwitch({"show clock": "12:00:00"}))
    monkeypatch.setattr(server, "run_show", lambda _command: "12:00:00")
    asyncio.run(server.mcp.call_tool("show", {"command": "show clock"}))
    start, result = _records(audit_log)
    assert start["phase"] == "start" and result["call_id"] == start["call_id"]
    asyncio.run(server.mcp.call_tool("audit_tail", {"n": 5}))
    records = _records(audit_log)
    assert [rec["tool"] for rec in records] == ["show", "show", "audit_tail", "audit_tail"]
    assert records[3]["call_id"] == records[2]["call_id"]


# -------------------------------------------------------------- mac table


def test_mac_table_count_note(monkeypatch: pytest.MonkeyPatch, reset_command_file: None) -> None:
    install(
        monkeypatch,
        FakeSwitch({"show mac-address-table": live.MAC, "show mac-address-table count": live.MAC_COUNT}),
    )
    data = json.loads(r.mac_table())
    assert data["matched"] == 2 and data["total_reported"] == 2
    assert "reports 3 dynamic addresses" in data["count_note"]
    install(
        monkeypatch,
        FakeSwitch({"show mac-address-table": s.MAC, "show mac-address-table count": s.MAC_COUNT}),
    )
    assert "count_note" not in json.loads(r.mac_table())


# ------------------------------------------------------------ port policy


def test_port_policy_text_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    from lgs_switch_mcp.validation import port_policy_text

    monkeypatch.setenv("SWITCH_PROTECTED_PORTS", "0/24,0/10")
    monkeypatch.setenv("SWITCH_CAUTION_PORTS", "0/15")
    text = port_policy_text()
    assert "Protected ports (SWITCH_PROTECTED_PORTS): 0/10, 0/24." in text
    assert "need confirm_caution_port=true): 0/15." in text
    monkeypatch.delenv("SWITCH_PROTECTED_PORTS")
    monkeypatch.setenv("SWITCH_CAUTION_PORTS", "0/99")
    text = port_policy_text()
    assert "SWITCH_PROTECTED_PORTS is unset or invalid" in text
    assert "SWITCH_CAUTION_PORTS is invalid" in text


def test_port_tool_descriptions_show_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    from lgs_switch_mcp import server, writetools

    monkeypatch.setenv("SWITCH_PROTECTED_PORTS", "0/10,0/24")
    monkeypatch.setenv("SWITCH_CAUTION_PORTS", "0/15")
    for function in (server.port_set_description, writetools.port_disable, writetools.poe_cycle):
        description = server.tool_description(function)
        assert "0/10, 0/24" in description and "0/15" in description
    assert "SWITCH_PROTECTED_PORTS" not in server.tool_description(server.show)


# ------------------------------------------------------------- environment


def test_health_summary_environment(
    monkeypatch: pytest.MonkeyPatch, reset_command_file: None
) -> None:
    install(
        monkeypatch,
        FakeSwitch(
            {
                "show system information": s.SYSTEM,
                "show device temperature": live.TEMPERATURE,
                "show system fan status": live.FAN,
                "show system utilization": live.UTILIZATION,
            }
        ),
    )
    data = json.loads(r.health_summary())
    env = data["environment"]
    assert env["temperature"]["rows"][0]["temperaturec"] == "41"
    assert env["fan"]["fields"]["Fan 1 Status"] == "OK"
    assert env["utilization"]["fields"]["Memory Utilization"] == "48 %"


def test_health_summary_without_environment_allowlist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from lgs_switch_mcp.toolkit import prepare_runtime

    commands = tmp_path / "commands.yml"
    commands.write_text(
        "allowed_commands:\n  - show system information\ndenied_commands:\n  - configure*\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("NETMIKO_MCP_COMMAND_FILE", str(commands))
    prepare_runtime()
    try:
        install(monkeypatch, FakeSwitch({"show system information": s.SYSTEM}))
        data = json.loads(r.health_summary())
        assert "environment" not in data
        assert not any("temperature" in error for error in data["errors"])
    finally:
        from tests.conftest import COMMANDS

        monkeypatch.setenv("NETMIKO_MCP_COMMAND_FILE", str(COMMANDS))
        prepare_runtime()


def test_environment_unavailable_marker() -> None:
    assert tables.parse_environment("% Invalid Command\n") == {"unavailable": "% Invalid Command"}


# ------------------------------------------------- 0.3.2: documented layouts


def test_environment_documented_layouts() -> None:
    """Layouts from the CLI reference of the same CLI family (Panasonic MU
    series, sections 3.77 and 3.83); the LGS live values match the format."""
    from lgs_switch_mcp.tables import parse_environment

    fan = parse_environment("\nSystem Fan Status: OK\n")
    assert fan["fields"]["System Fan Status"] == "OK"
    temperature = parse_environment(
        "Sensor local temperature : 42 °C\nSensor remote temperature : 37 °C\n"
    )
    assert temperature["fields"]["Sensor local temperature"] == "42 °C"
    incomplete = parse_environment("% Incomplete command.\n")
    assert incomplete == {"unavailable": "% Incomplete command."}
