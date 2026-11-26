"""0.3.0 write tools: dry run, protected/caution ports, snapshot, builders."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from netmiko_mcp_linksys import commands as c
from netmiko_mcp_linksys import writetools as w
from tests.fakes import RUNNING_CONFIG, SECRETS_IN_RUNNING, FakeSwitch, install

# ------------------------------------------------------------------ builders


def test_builders_follow_iss_syntax() -> None:
    assert c.build_port_security_commands("0/3", 5) == ["interface gigabitethernet 0/3", "port-security 5"]
    assert c.build_port_security_commands("0/3", None)[1] == "no port-security"
    assert c.build_storm_control_commands("0/3", "dlf", 500)[1] == "storm-control dlf level 500"
    assert c.build_storm_control_commands("0/3", "broadcast", None)[1] == "no storm-control broadcast level"
    assert c.build_rate_limit_commands("0/3", "output", 1000)[1] == "rate-limit output 1000"
    assert c.build_rate_limit_commands("0/3", "input", None)[1] == "no rate-limit input"
    assert c.build_syslog_commands("192.0.2.5", 514, "local0", "informational", True) == [
        "logging-server facility local0 severity informational ipv4 192.0.2.5 port 514",
        "logging-service enable",
        "logging severity informational",
    ]
    assert c.build_syslog_commands("192.0.2.5", 514, "local0", "informational", False) == [
        "no logging-server facility local0 severity informational ipv4 192.0.2.5 port 514"
    ]
    assert c.build_identity_commands("Rack 1", "ops", "core-sw") == [
        'system location "Rack 1"',
        "system contact ops",
        "set switch-name core-sw",
    ]
    assert c.build_clear_counters_command(None) == "clear counters"
    assert c.build_clear_counters_command("0/4") == "clear counters gigabitethernet 0/4"


# ----------------------------------------------------------- tool matrix

PORT_TOOLS: list[tuple[str, dict[str, Any]]] = [
    ("port_security_set", {"limit": 4}),
    ("storm_control_set", {"storm_type": "broadcast", "level_pps": 1000}),
    ("rate_limit_set", {"direction": "input", "kbps": 10000}),
    ("poe_cycle", {}),
    ("cable_diag", {}),
    ("clear_counters", {}),
]
ALL_PORT_WRITE_TOOLS = PORT_TOOLS + [
    ("port_enable", {}),
    ("port_disable", {}),
    ("poe_enable", {}),
    ("poe_disable", {}),
]


@pytest.mark.parametrize(("tool", "kwargs"), PORT_TOOLS)
@pytest.mark.parametrize("port", ["0/10", "0/24"])
def test_new_port_tools_refuse_protected_ports(
    tool: str, kwargs: dict[str, Any], port: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SWITCH_PROTECTED_PORTS", "0/10,0/24")
    switch = install(monkeypatch, FakeSwitch({}))
    for dry_run in (True, False):
        result = getattr(w, tool)(port=port, dry_run=dry_run, **kwargs)
        assert result.startswith("Rejected:"), result
        assert f"protected port {port}" in result
    assert switch.sessions == 0


@pytest.mark.parametrize(("tool", "kwargs"), PORT_TOOLS)
def test_new_port_tools_fail_closed_without_protected_list(
    tool: str, kwargs: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SWITCH_PROTECTED_PORTS", raising=False)
    switch = install(monkeypatch, FakeSwitch({}))
    result = getattr(w, tool)(port="0/3", dry_run=False, **kwargs)
    assert result.startswith("Rejected:")
    assert switch.sessions == 0


@pytest.mark.parametrize(("tool", "kwargs"), ALL_PORT_WRITE_TOOLS)
def test_caution_port_needs_confirmation(
    tool: str, kwargs: dict[str, Any], audit_log, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SWITCH_CAUTION_PORTS", "0/15")
    switch = install(monkeypatch, FakeSwitch({}))
    refused = getattr(w, tool)(port="0/15", **kwargs)
    assert refused.startswith("Rejected:") and "caution port" in refused
    assert switch.sessions == 0
    allowed = getattr(w, tool)(port="0/15", confirm_caution_port=True, **kwargs)
    assert not allowed.startswith("Rejected:"), allowed
    assert "caution port" in allowed
    record = json.loads(audit_log.read_text().splitlines()[-1])
    assert record["params"]["confirm_caution_port"] is True


def test_invalid_caution_list_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_CAUTION_PORTS", "gi0/15")
    install(monkeypatch, FakeSwitch({}))
    assert w.poe_enable("0/3").startswith("Rejected:")


DRY_RUN_CALLS: list[tuple[str, dict[str, Any]]] = [
    (name, {"port": "0/3", **kwargs}) for name, kwargs in ALL_PORT_WRITE_TOOLS
] + [
    ("syslog_set", {"server_ip": "192.0.2.5"}),
    ("mgmt_services_set", {"https": True, "http": False, "disable_telnet": True}),
    ("system_identity_set", {"location": "Rack 1", "contact": "ops", "name": "sw1"}),
    ("clear_counters", {}),
]


@pytest.mark.parametrize(("tool", "kwargs"), DRY_RUN_CALLS)
def test_dry_run_is_default_and_sends_nothing(
    tool: str, kwargs: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SWITCH_SYSLOG_ALLOWED", "192.0.2.5")
    monkeypatch.setenv("SWITCH_PRE_WRITE_SNAPSHOT", "required")
    switch = install(monkeypatch, FakeSwitch({"show current running-config": RUNNING_CONFIG}))
    result = json.loads(getattr(w, tool)(**kwargs))
    assert result["dry_run"] is True
    assert result["sent"] is False
    assert result["commands"]
    assert switch.config_sets == []
    assert not any(s.startswith(("clear", "show interface cable-diag")) for s in switch.shows)


# ------------------------------------------------------ snapshot / errors


def test_snapshot_required_refuses_when_running_config_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SWITCH_PRE_WRITE_SNAPSHOT", "required")
    switch = install(monkeypatch, FakeSwitch({}))
    result = w.port_security_set("0/3", 4, dry_run=False)
    assert result.startswith("Error: Pre-write snapshot failed, nothing was sent")
    assert switch.config_sets == []


def test_snapshot_best_effort_writes_and_reports(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_PRE_WRITE_SNAPSHOT", "best-effort")
    switch = install(monkeypatch, FakeSwitch({}))
    result = json.loads(w.port_security_set("0/3", 4, dry_run=False))
    assert "failed" in result["snapshot"]
    assert switch.config_sets == [["interface gigabitethernet 0/3", "port-security 4"]]


def test_snapshot_is_masked_file(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_PRE_WRITE_SNAPSHOT", "required")
    install(monkeypatch, FakeSwitch({"show current running-config": RUNNING_CONFIG}))
    result = json.loads(w.storm_control_set("0/3", "broadcast", 2000, dry_run=False))
    path = result["snapshot"]["path"]
    assert path.startswith(str(tmp_path / "backups"))
    assert path.endswith("_running_pre-storm_control_set.cfg")
    body = Path(path).read_text(encoding="utf-8")
    for secret in SECRETS_IN_RUNNING:
        assert secret not in body
        assert secret not in json.dumps(result)
    assert result["interface_config_before"].splitlines()[0] == "interface gigabitethernet 0/3"


def test_device_error_percent_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    switch = install(monkeypatch, FakeSwitch({}, reject="rate-limit"))
    result = w.rate_limit_set("0/3", "input", 5000, dry_run=False)
    assert result.startswith("Error: Device rejected the configuration sequence")
    assert switch.config_kwargs[0]["error_pattern"] == "%"


def test_storm_control_reads_interface_block(monkeypatch: pytest.MonkeyPatch) -> None:
    after = RUNNING_CONFIG.replace("storm-control broadcast level 1000", "storm-control broadcast level 2000")
    install(monkeypatch, FakeSwitch({"show current running-config": [RUNNING_CONFIG, after]}))
    result = json.loads(w.storm_control_set("0/3", "broadcast", 2000, dry_run=False))
    diff = result["diff"]["interface config"]
    assert "-storm-control broadcast level 1000" in diff
    assert "+storm-control broadcast level 2000" in diff


@pytest.mark.parametrize(
    ("tool", "kwargs", "message"),
    [
        ("port_security_set", {"port": "0/3", "limit": 0}, "limit"),
        ("port_security_set", {"port": "0/3", "limit": 257}, "limit"),
        ("storm_control_set", {"port": "0/3", "storm_type": "multicast"}, "storm_type"),
        ("rate_limit_set", {"port": "0/3", "direction": "both"}, "direction"),
        ("rate_limit_set", {"port": "0/3", "direction": "input", "kbps": 80_000_001}, "kbps"),
        ("poe_cycle", {"port": "0/3", "off_seconds": 1}, "off_seconds"),
        ("poe_cycle", {"port": "0/3", "off_seconds": 61}, "off_seconds"),
        ("poe_cycle", {"port": "0/26"}, "PoE is only supported"),
        ("port_enable", {"port": "0/3", "dry_run": "no"}, "dry_run"),
        ("system_identity_set", {"location": "bad;value"}, "location"),
        ("system_identity_set", {"name": "has space"}, "switch name"),
        ("system_identity_set", {}, "Nothing to change"),
        ("mgmt_services_set", {}, "Nothing to change"),
        ("mgmt_services_set", {"http": False, "https": False}, "Refusing"),
    ],
)
def test_parameter_validation(
    tool: str, kwargs: dict[str, Any], message: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    switch = install(monkeypatch, FakeSwitch({}))
    result = getattr(w, tool)(**kwargs)
    assert result.startswith("Rejected:") and message in result, result
    assert switch.sessions == 0


# ------------------------------------------------------------- syslog


def test_syslog_requires_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, FakeSwitch({}))
    assert "SWITCH_SYSLOG_ALLOWED is not set" in w.syslog_set("192.0.2.5")
    monkeypatch.setenv("SWITCH_SYSLOG_ALLOWED", "192.0.2.5,not-an-ip")
    assert "invalid IPv4" in w.syslog_set("192.0.2.5")
    monkeypatch.setenv("SWITCH_SYSLOG_ALLOWED", "192.0.2.5")
    assert "not in SWITCH_SYSLOG_ALLOWED" in w.syslog_set("192.0.2.6")


def test_syslog_set_and_remove(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_SYSLOG_ALLOWED", "192.0.2.5")
    switch = install(monkeypatch, FakeSwitch({"show logging-server": "x", "show logging": "y"}))
    added = json.loads(w.syslog_set("192.0.2.5", severity="warnings", dry_run=False))
    assert added["commands"][0] == (
        "logging-server facility local0 severity warnings ipv4 192.0.2.5 port 514"
    )
    removed = json.loads(w.syslog_set("192.0.2.5", enabled=False, dry_run=False))
    assert removed["commands"][0].startswith("no logging-server facility local0")
    assert len(switch.config_sets) == 2
    assert "Rejected" in w.syslog_set("192.0.2.5", severity="notifications")


# ---------------------------------------------------------------- mgmt


def test_http_disable_needs_https_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    switch = install(
        monkeypatch,
        FakeSwitch({"show ip http secure server status": "HTTPS server status : Disabled"}),
    )
    result = w.mgmt_services_set(http=False, dry_run=False)
    assert result.startswith("Rejected:") and "HTTPS was not read back as Enabled" in result
    assert switch.config_sets == []


def test_https_enable_then_http_disable(monkeypatch: pytest.MonkeyPatch) -> None:
    switch = install(
        monkeypatch,
        FakeSwitch(
            {
                "show ip http secure server status": [
                    "HTTPS server status : Disabled",  # before
                    "HTTPS server status : Enabled",  # guard
                    "HTTPS server status : Enabled",  # after
                ],
                "show http server status": "HTTP server status : Enabled",
                "show telnet server": "Telnet server : Disabled",
            }
        ),
    )
    result = json.loads(w.mgmt_services_set(http=False, https=True, dry_run=False))
    assert switch.config_sets == [["ip http secure server"], ["set ip http disable"]]
    assert result["sent"] is True


def test_https_failure_keeps_http_and_reports_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    switch = install(
        monkeypatch,
        FakeSwitch({"show ip http secure server status": "HTTPS server status : Disabled"}),
    )
    result = w.mgmt_services_set(http=False, https=True, dry_run=False)
    assert result.startswith("Error: Stopped after sending ['ip http secure server']")
    assert switch.config_sets == [["ip http secure server"]]


def test_mgmt_never_offers_ssh_or_telnet_on() -> None:
    import inspect

    params = set(inspect.signature(w.mgmt_services_set).parameters)
    assert params == {"http", "https", "disable_telnet", "dry_run"}


# ------------------------------------------------------------ poe_cycle


def test_poe_cycle_off_wait_on(monkeypatch: pytest.MonkeyPatch) -> None:
    sleeps: list[float] = []
    monkeypatch.setattr(w.time, "sleep", sleeps.append)
    switch = install(monkeypatch, FakeSwitch({"show power inline gigabitethernet 0/3": "On"}))
    result = json.loads(w.poe_cycle("0/3", off_seconds=7, dry_run=False))
    assert switch.config_sets == [
        ["interface gigabitethernet 0/3", "power inline disable"],
        ["interface gigabitethernet 0/3", "power inline enable"],
    ]
    assert sleeps == [7]
    assert result["sent"] is True


def test_poe_cycle_reenables_when_wait_is_interrupted(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_seconds: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(w.time, "sleep", boom)
    switch = install(monkeypatch, FakeSwitch({}))
    with pytest.raises(KeyboardInterrupt):
        w.poe_cycle("0/3", dry_run=False)
    assert switch.config_sets[-1] == ["interface gigabitethernet 0/3", "power inline enable"]


def test_poe_cycle_retries_enable_in_new_session(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(w.time, "sleep", lambda _s: None)
    switch = install(monkeypatch, FakeSwitch({}))
    calls = {"n": 0}
    real = w._set_poe

    def flaky(conn: Any, port: str, enabled: bool) -> str:
        if enabled:
            calls["n"] += 1
            if calls["n"] == 1:
                raise w.SwitchConnectionError("channel closed")
        return real(conn, port, enabled)

    monkeypatch.setattr(w, "_set_poe", flaky)
    result = json.loads(w.poe_cycle("0/3", dry_run=False))
    assert calls["n"] == 2
    assert switch.sessions == 2
    assert result["sent"] is True


def test_poe_cycle_reports_left_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(w.time, "sleep", lambda _s: None)
    install(monkeypatch, FakeSwitch({}))
    real = w._set_poe

    def broken(conn: Any, port: str, enabled: bool) -> str:
        if enabled:
            raise w.SwitchConnectionError("no route")
        return real(conn, port, enabled)

    monkeypatch.setattr(w, "_set_poe", broken)
    result = w.poe_cycle("0/3", dry_run=False)
    assert "may be left DISABLED" in result
    assert "poe_enable(port='0/3', dry_run=false)" in result


# ------------------------------------------------ cable_diag / counters


def test_cable_diag_runs_only_when_not_dry(monkeypatch: pytest.MonkeyPatch) -> None:
    command = "show interface cable-diag gigabitethernet 0/3"
    switch = install(monkeypatch, FakeSwitch({command: "Pair A OK 3m"}))
    dry = json.loads(w.cable_diag("0/3"))
    assert dry["sent"] is False and command not in switch.shows
    assert any("interrupt the link" in item for item in dry["warnings"])
    real = json.loads(w.cable_diag("0/3", dry_run=False))
    assert real["output"] == "Pair A OK 3m"


def test_clear_counters_exec_and_resets_delta_baseline(monkeypatch: pytest.MonkeyPatch) -> None:
    from netmiko_mcp_linksys import configstore

    configstore.write_state(w.COUNTERS_STATE, {"time": "t", "counters": {}})
    switch = install(monkeypatch, FakeSwitch({"clear counters": "", "show interfaces counters": "x"}))
    result = json.loads(w.clear_counters(dry_run=False))
    assert "clear counters" in switch.shows
    assert switch.config_sets == []
    assert result["sent"] is True
    assert configstore.read_state(w.COUNTERS_STATE) is None


def test_clear_counters_device_error(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, FakeSwitch({"show interfaces counters": "x"}))
    result = w.clear_counters("0/3", dry_run=False)
    assert result.startswith("Error: Device rejected 'clear counters gigabitethernet 0/3'")


# ------------------------------------------------------------- identity


def test_identity_name_refreshes_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    switch = install(monkeypatch, FakeSwitch({"show system information": "x"}))
    json.loads(w.system_identity_set(location="Rack 1", name="sw1", dry_run=False))
    assert switch.config_sets == [['system location "Rack 1"', "set switch-name sw1"]]
    assert switch.prompt_refreshed is True


# --------------------------------------------------------- SNMP dry run


def test_snmp_tools_default_to_dry_run(monkeypatch: pytest.MonkeyPatch) -> None:
    from netmiko_mcp_linksys import server
    from tests.test_snmp import (
        ACCESS_SHOW_RW,
        READBACK_SNMP_ACCESS,
        READBACK_SNMP_VIEW,
        VIEW_SHOW_RESTRICTED,
        _fake_snmp_session,
    )

    monkeypatch.setenv("SWITCH_SNMP_WRITE_ENABLED", "1")
    sent: list[list[str]] = []
    session = _fake_snmp_session(
        {READBACK_SNMP_ACCESS: ACCESS_SHOW_RW, READBACK_SNMP_VIEW: VIEW_SHOW_RESTRICTED}, sent
    )
    with patch.object(server, "run_in_session", side_effect=session):
        result = json.loads(server.snmp_view_create("ifmib", "interfaces"))
    assert sent == []
    assert result["dry_run"] is True
    assert result["commands"] == ["snmp view ifmib 1.3.6.1.2.1.2 included"]


def test_snmp_community_dry_run_hides_secret(audit_log, monkeypatch: pytest.MonkeyPatch) -> None:
    from netmiko_mcp_linksys import server
    from tests.test_snmp import (
        ACCESS_SHOW_RW,
        READBACK_SNMP_ACCESS,
        READBACK_SNMP_VIEW,
        SECRET,
        VIEW_SHOW_RESTRICTED,
        _fake_snmp_session,
    )

    monkeypatch.setenv("SWITCH_SNMP_WRITE_ENABLED", "1")
    monkeypatch.setenv("SWITCH_SNMP_COMMUNITY", SECRET)
    sent: list[list[str]] = []
    shows = {READBACK_SNMP_ACCESS: ACCESS_SHOW_RW, READBACK_SNMP_VIEW: VIEW_SHOW_RESTRICTED}
    with patch.object(server, "run_in_session", side_effect=_fake_snmp_session(shows, sent)):
        result = server.snmp_community_create("ifmib", "ro")
    assert sent == []
    assert SECRET not in result
    assert SECRET not in audit_log.read_text(encoding="utf-8")
    data = json.loads(result)
    assert data["dry_run"] is True and data["sent"] is False
    assert any("[REDACTED]" in line for line in data["commands"])


def test_snmp_real_run_takes_snapshot_before_first_send(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from netmiko_mcp_linksys import server
    from tests.test_snmp import (
        ACCESS_SHOW_RW,
        READBACK_SNMP_ACCESS,
        READBACK_SNMP_VIEW,
        VIEW_SHOW_RESTRICTED,
        _fake_snmp_session,
    )

    monkeypatch.setenv("SWITCH_SNMP_WRITE_ENABLED", "1")
    monkeypatch.setenv("SWITCH_PRE_WRITE_SNAPSHOT", "required")
    order: list[str] = []
    monkeypatch.setattr(
        server.writes, "take_snapshot",
        lambda _conn, tool: order.append(f"snapshot:{tool}") or {"path": "/x"},
    )
    sent: list[list[str]] = []
    shows = {READBACK_SNMP_ACCESS: ACCESS_SHOW_RW, READBACK_SNMP_VIEW: VIEW_SHOW_RESTRICTED}
    with patch.object(server, "run_in_session", side_effect=_fake_snmp_session(shows, sent)):
        result = server.snmp_view_create("ifmib", "interfaces", dry_run=False)
    assert order == ["snapshot:snmp_view_create"]
    assert sent == [["snmp view ifmib 1.3.6.1.2.1.2 included"]]
    assert 'pre-write snapshot: {"path": "/x"}' in result


def test_poe_cycle_never_enables_when_off_was_not_attempted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from netmiko_mcp_linksys.connection import SwitchConnectionError

    switch = install(monkeypatch, FakeSwitch({}))

    def broken_read(_conn: Any, _command: str) -> str:
        raise SwitchConnectionError("read timeout")

    monkeypatch.setattr(w, "send_paged_redacted", broken_read)
    result = w.poe_cycle("0/3", dry_run=False)
    assert result.startswith("Error: read timeout Nothing was sent.")
    assert switch.config_sets == []
