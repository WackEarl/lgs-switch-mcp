"""0.3.0 read tools, parsers, config store, audit_tail and show_help."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from pathlib import Path

import pytest

from netmiko_mcp_linksys import configstore
from netmiko_mcp_linksys import readtools as r
from tests import samples_iss as s
from tests.fakes import RUNNING_CONFIG, SECRETS_IN_RUNNING, FakeSwitch, install

ALL_SHOWS = {
    "show system information": s.SYSTEM,
    "show power detail": s.POWER_DETAIL_KV,
    "show power inline": s.POWER_INLINE,
    "show interfaces status": s.STATUS,
    "show interfaces counters": s.COUNTERS,
    "show logging": s.LOGGING,
    "show interfaces description": s.DESCRIPTION,
    "show vlan": s.VLAN,
    "show lldp neighbors": s.LLDP,
    "show mac-address-table": s.MAC,
    "show mac-address-table count": s.MAC_COUNT,
}


@pytest.fixture
def switch(monkeypatch: pytest.MonkeyPatch, reset_command_file: None) -> FakeSwitch:
    return install(monkeypatch, FakeSwitch(dict(ALL_SHOWS)))


def test_health_summary(switch: FakeSwitch) -> None:
    data = json.loads(r.health_summary(log_entries=1))
    assert switch.sessions == 1
    assert data["uptime"] == "35 days, 4 hours, 12 minutes"
    assert data["config_save_status"] == "Saved"
    assert data["poe"]["budget_w"] == 250.0 and data["poe"]["consumed_w"] == 67.6
    assert data["poe"]["ports_w"] == {"0/1": 5.4, "0/15": 3.1}
    assert data["ports_up"] == ["0/1", "0/15"] and data["ports_down"] == ["0/2"]
    assert data["ports"]["0/1"] == {"link": "up", "speed": "1000", "duplex": "Full"}
    assert data["ports_with_errors"] == {"0/15": {"indiscards": 115, "inerrs": 21}}
    assert data["log_entries"] == ["<2>Nov 26 11:05:00 LGS328PC: Port Gi0/2 link down"]
    assert data["errors"] == [] and data["parse_warnings"] == []
    assert "raw" not in data


def test_health_summary_partial_failure(monkeypatch: pytest.MonkeyPatch, reset_command_file: None) -> None:
    install(monkeypatch, FakeSwitch({"show system information": s.SYSTEM}))
    data = json.loads(r.health_summary(include_raw=True))
    assert data["config_save_status"] == "Saved"
    assert "show system information" in data["raw"]
    assert data["parse_warnings"]  # unrecognised tables are reported


def test_port_status(switch: FakeSwitch) -> None:
    ports = {p["port"]: p for p in json.loads(r.port_status())["ports"]}
    assert ports["0/1"]["description"] == "AP-Floor1"
    assert ports["0/1"]["vlans"] == [{"vlan": 1, "tagged": False}]
    assert ports["0/1"]["poe"]["power_w"] == 5.4
    assert ports["0/1"]["lldp"] == [{"device_id": "ap-floor1", "port_id": "eth0"}]
    assert ports["0/24"]["lldp"][0]["device_id"] == "fritz.box"
    assert ports["0/2"]["link"] == "down"


def test_port_counters_filter(switch: FakeSwitch) -> None:
    data = json.loads(r.port_counters("0/15"))
    assert list(data["counters"]) == ["0/15"]
    assert data["counters"]["0/15"]["inerrs"] == 21
    assert r.port_counters("15").startswith("Rejected:")


def test_counters_delta(switch: FakeSwitch) -> None:
    first = json.loads(r.counters_delta())
    assert first["baseline"] is True
    switch.outputs["show interfaces counters"] = s.COUNTERS2
    second = json.loads(r.counters_delta())
    assert second["new_errors"] == {"0/15": {"indiscards": 3, "inerrs": 4}}
    assert second["deltas"]["0/15"] == {"indiscards": 3, "inerrs": 4}
    switch.outputs["show interfaces counters"] = s.COUNTERS
    third = json.loads(r.counters_delta())
    assert third["counters_reset"] == ["0/15"]


def test_counters_state_file_is_private(switch: FakeSwitch, tmp_path) -> None:
    r.counters_delta()
    path = tmp_path / "state" / r.COUNTERS_STATE
    assert path.is_file()
    assert (path.stat().st_mode & 0o777) == 0o600
    assert (path.parent.stat().st_mode & 0o777) == 0o700


def test_mac_table_filters(switch: FakeSwitch) -> None:
    by_port = json.loads(r.mac_table(port="0/15"))
    assert [e["mac"] for e in by_port["entries"]] == ["00:11:22:aa:bb:02"]
    by_mac = json.loads(r.mac_table(mac="0011.22AA.BB01"))
    assert by_mac["matched"] == 1 and by_mac["entries"][0]["port"] == "0/1"
    assert by_mac["count"]["Total Mac Addresses"] == 2
    assert r.mac_table(mac="zz").startswith("Rejected:")


def test_lldp_and_poe(switch: FakeSwitch) -> None:
    assert len(json.loads(r.lldp_neighbors())["neighbors"]) == 2
    poe = json.loads(r.poe_status())
    assert poe["budget_w"] == 250.0 and poe["ports"]["0/15"]["class"] == "1"


def test_read_tools_respect_allowlist(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    from netmiko_mcp_linksys.toolkit import prepare_runtime

    narrow = tmp_path / "commands.yml"
    narrow.write_text("allowed_commands:\n  - show system information\ndenied_commands: []\n")
    monkeypatch.setenv("NETMIKO_MCP_COMMAND_FILE", str(narrow))
    prepare_runtime()
    switch = install(monkeypatch, FakeSwitch(dict(ALL_SHOWS)))
    try:
        data = json.loads(r.health_summary())
    finally:
        monkeypatch.undo()
        prepare_runtime()
    assert switch.shows == ["show system information"]
    assert any("Command rejected" in e for e in data["errors"])


def test_read_tool_without_command_file(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NETMIKO_MCP_COMMAND_FILE", raising=False)
    assert "NETMIKO_MCP_COMMAND_FILE" in r.port_status()


# ------------------------------------------------------------- config


def test_config_read_is_masked(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, FakeSwitch({"show current running-config": RUNNING_CONFIG}))
    data = json.loads(r.config_read())
    for secret in SECRETS_IN_RUNNING:
        assert secret not in data["config"]
    assert data["sha256"] == configstore.sha256_text(data["config"])
    assert r.config_read("current").startswith("Rejected:")


def test_config_read_uses_show_current_running_config(monkeypatch: pytest.MonkeyPatch) -> None:
    switch = install(monkeypatch, FakeSwitch({"show current running-config": RUNNING_CONFIG}))
    json.loads(r.config_read("running"))
    # 0.3.2: the background dump also reads the Config Save Status for config_diff.
    assert switch.shows == ["show current running-config", "show system information"]


def test_config_read_startup_is_not_available(monkeypatch: pytest.MonkeyPatch) -> None:
    switch = install(monkeypatch, FakeSwitch({"show current running-config": RUNNING_CONFIG}))
    for result in (r.config_read("startup"), r.config_backup("startup")):
        assert result.startswith("Not available: startup-config cannot be read on this device")
    assert switch.shows == []  # nothing is sent for startup


def test_config_read_rejected_running(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, FakeSwitch({}))
    result = r.config_read("running")
    assert result.startswith("Error: show current running-config is not available")


def test_config_backup_and_diff_to_previous(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    changed = RUNNING_CONFIG.replace("Default Location", "Rack 2")
    install(monkeypatch, FakeSwitch({"show current running-config": [RUNNING_CONFIG, changed]}))
    first = json.loads(r.config_backup())
    assert re.search(r"/\d{4}-\d{2}-\d{2}_\d{4}_running\.cfg$", first["path"])
    assert first["previous"] is None
    second = json.loads(r.config_backup())
    assert second["path"] != first["path"]
    assert second["previous"] == first["path"]
    assert second["changed_since_previous"] is True
    assert "+system location Rack 2" in second["diff"]
    body = Path(second["path"]).read_text(encoding="utf-8")
    for secret in SECRETS_IN_RUNNING:
        assert secret not in body
    assert (os.stat(second["path"]).st_mode & 0o777) == 0o600
    assert r.config_backup(tag="bad tag").startswith("Rejected:")


def test_config_diff_against_last_save_copy(monkeypatch: pytest.MonkeyPatch) -> None:
    changed = RUNNING_CONFIG.replace("Default Location", "Rack 2")
    saved = configstore.store_backup(
        json.loads(_masked_running(monkeypatch))["config"], "running", tag="pre-save"
    )
    switch = install(
        monkeypatch,
        FakeSwitch(
            {
                "show current running-config": changed,
                "show system information": "Config Save Status : Not Saved",
            }
        ),
    )
    data = json.loads(r.config_diff())
    assert data["baseline"] == saved["path"]
    assert data["unsaved_changes"] is True
    assert data["config_save_status"] == "Not Saved"
    assert "-system location Default Location" in data["diff"]
    assert "+system location Rack 2" in data["diff"]
    assert data["startup_config"] == "not readable on this device"
    assert "show startup-config" not in switch.shows


def test_config_diff_without_baseline(monkeypatch: pytest.MonkeyPatch) -> None:
    install(
        monkeypatch,
        FakeSwitch(
            {
                "show current running-config": RUNNING_CONFIG,
                "show system information": "Config Save Status : Successful",
            }
        ),
    )
    data = json.loads(r.config_diff())
    assert data["unsaved_changes"] is None and data["diff"] is None
    assert data["config_save_status"] == "Successful"
    assert "save_config" in data["note"]


def _masked_running(monkeypatch: pytest.MonkeyPatch) -> str:
    install(monkeypatch, FakeSwitch({"show current running-config": RUNNING_CONFIG}))
    return r.config_read()


def test_latest_backup_by_tag() -> None:
    a = configstore.store_backup("a\n", "running", tag="pre-save")
    configstore.store_backup("b\n", "running", tag="pre-save_config")
    configstore.store_backup("c\n", "running", tag="pre-port_enable")
    assert str(configstore.latest_backup("running", tag="pre-save")) == a["path"]
    assert configstore.latest_backup("running", tag="nothing") is None


def test_backup_name_and_collision(tmp_path) -> None:
    now = datetime(2026, 11, 26, 21, 5)
    assert configstore.backup_name("running", now=now) == "2026-11-26_2105_running.cfg"
    assert configstore.backup_name("startup", tag="pre-save", now=now) == (
        "2026-11-26_2105_startup_pre-save.cfg"
    )
    a = configstore.store_backup("x\n", "running")
    b = configstore.store_backup("x\n", "running")
    assert a["path"] != b["path"]
    assert b["changed_since_previous"] is False and b["diff"] == ""


def test_unified_diff_is_capped() -> None:
    before = "\n".join(f"a{i}" for i in range(1000))
    after = "\n".join(f"b{i}" for i in range(1000))
    diff = configstore.unified_diff(before, after, before_label="x", after_label="y")
    assert len(diff.splitlines()) <= configstore.MAX_DIFF_LINES + 1
    assert "more diff lines not shown" in diff.splitlines()[-1]


# ------------------------------------------------------------ audit_tail


def test_audit_tail(audit_log, monkeypatch: pytest.MonkeyPatch) -> None:
    from netmiko_mcp_linksys.audit import write_audit

    for i in range(5):
        write_audit(tool=f"t{i}", params={}, allowed=True, result="ok")
    audit_log.open("a").write("not json dummy-password-not-real\n")
    data = json.loads(r.audit_tail(3))
    assert [e.get("tool") for e in data["entries"][:2]] == ["t3", "t4"]
    assert "dummy-password-not-real" not in json.dumps(data)
    assert r.audit_tail(0).startswith("Rejected:")
    assert r.audit_tail(501).startswith("Rejected:")


def test_audit_tail_without_log(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SWITCH_AUDIT_LOG", raising=False)
    assert r.audit_tail().startswith("Error: SWITCH_AUDIT_LOG is not set")


# ------------------------------------------------------------- show_help


def test_show_help_validates_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    typed: list[str] = []
    monkeypatch.setattr(r, "send_help", lambda _conn, line: typed.append(line) or "env  Environment")
    install(monkeypatch, FakeSwitch({}))
    data = json.loads(r.show_help("show  Interfaces"))
    assert typed == ["show interfaces"]
    assert data["typed"] == "show interfaces ?"
    for bad in ("interfaces; reload", "a|b", "x" * 0 + "1abc", "a b c d e f"):
        assert r.show_help(bad).startswith("Rejected:"), bad
    assert typed == ["show interfaces"]


class _HelpChannel:
    """Scripted channel for send_help: returns the help listing once."""

    base_prompt = "LGS328PC"
    RETURN = "\n"

    def __init__(self) -> None:
        self.written: list[str] = []
        self.chunks = ["show ?\r\n  interfaces  Interface status\r\n  vlan  VLAN\r\nLGS328PC# show "]

    def clear_buffer(self) -> None:
        pass

    def write_channel(self, data: str) -> None:
        self.written.append(data)
        if data == "\n":
            self.chunks.append("\r\nLGS328PC# ")

    def read_channel(self) -> str:
        return self.chunks.pop(0) if self.chunks else ""


def test_send_help_never_submits_the_line(monkeypatch: pytest.MonkeyPatch) -> None:
    from netmiko_mcp_linksys import connection

    monkeypatch.setenv("SWITCH_READ_TIMEOUT", "1")
    chan = _HelpChannel()
    out = connection.send_help(chan, "show", idle=0.2)
    assert chan.written[0] == "show ?"
    assert chan.written[1] == connection.CLEAR_LINE
    # Enter only after Ctrl-U cleared the typed text.
    assert chan.written[2] == "\n"
    assert "interfaces  Interface status" in out
    assert "LGS328PC#" not in out


