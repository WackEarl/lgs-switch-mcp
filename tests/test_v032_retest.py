"""0.3.2: fixes from the read-only retest of 0.3.1 (fakes and redacted
raw output only, never a device)."""

from __future__ import annotations

import asyncio
import json
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from netmiko_mcp_linksys import configdump, connection, server, tables
from netmiko_mcp_linksys import readtools as r
from netmiko_mcp_linksys.connection import (
    SwitchConnectionError,
    call_budget,
    call_deadline,
    connect_params,
    remaining_budget,
    run_show,
    send_paged,
    session,
)
from netmiko_mcp_linksys.validation import (
    ValidationError,
    canonical_port,
    reject_protected_port,
    require_caution_confirmation,
    validate_port,
)
from tests import samples_iss as s
from tests.fakes import RUNNING_CONFIG, FakeSwitch, install

RAW = Path(__file__).parent / "fixtures" / "lgs_031"


def raw(name: str) -> str:
    return (RAW / name).read_text(encoding="utf-8")


def call(tool: str, arguments: dict[str, Any]) -> str:
    """Call a registered tool the way the hub does (MCP, keyword args)."""
    result = asyncio.run(server.mcp.call_tool(tool, arguments))
    return result.content[0].text


# ------------------------------------------------- 4: PoE admin / auto_class


def test_power_inline_live_layout_fills_admin_and_auto_class() -> None:
    ports, warnings = tables.parse_power_inline(raw("show-power-inline.txt"))
    assert warnings == []
    assert sorted(ports, key=lambda p: int(p.split("/")[1])) == [f"0/{n}" for n in range(1, 25)]
    assert ports["0/1"] == {
        "admin": "up",
        "status": "Delivering",
        "power_w": 10.0,
        "max_power_w": None,
        "class": "4",
        "auto_class": "Enabled",
        "limit_type": "Auto Class",
        "device": None,
        "priority": "medium",
    }
    assert ports["0/12"]["class"] == "0" and ports["0/12"]["power_w"] == 1.9
    assert ports["0/2"]["status"] == "Searching" and ports["0/2"]["admin"] == "up"
    assert all(info["admin"] is not None for info in ports.values())
    assert all(info["auto_class"] is not None for info in ports.values())


def test_power_inline_other_limit_type_is_not_auto_class() -> None:
    text = raw("show-power-inline.txt").replace(
        "15     up     medium    Auto Class  ", "15     down   medium    User Defined"
    )
    ports, _ = tables.parse_power_inline(text)
    assert ports["0/15"]["limit_type"] == "User Defined"
    assert ports["0/15"]["auto_class"] == "Disabled"
    assert ports["0/15"]["admin"] == "down"
    assert ports["0/1"]["auto_class"] == "Enabled"


def test_poe_status_with_live_output(
    monkeypatch: pytest.MonkeyPatch, reset_command_file: None
) -> None:
    install(
        monkeypatch,
        FakeSwitch(
            {
                "show power detail": raw("show-power-detail.txt"),
                "show power inline": raw("show-power-inline.txt"),
            }
        ),
    )
    data = json.loads(r.poe_status())
    assert data["budget_w"] == 250 and data["consumed_w"] == 62.2
    assert data["parse_warnings"] == []
    assert data["ports"]["0/10"]["admin"] == "up"
    assert data["ports"]["0/10"]["auto_class"] == "Enabled"


# ------------------------------------------------------ 3: fan in health


def test_health_summary_fan_from_live_output(
    monkeypatch: pytest.MonkeyPatch, reset_command_file: None
) -> None:
    install(
        monkeypatch,
        FakeSwitch(
            {
                "show system information": s.SYSTEM,
                "show device temperature": raw("show-device-temperature.txt"),
                "show system fan status": raw("show-system-fan-status.txt"),
                "show system utilization": raw("show-system-utilization.txt"),
            }
        ),
    )
    data = json.loads(r.health_summary())
    env = data["environment"]
    assert env["fan"] == {"fields": {"System Fan Status": "OK"}}
    assert env["temperature"]["fields"]["Sensor local temperature"] == "41 °C"
    assert env["utilization"]["fields"]["used"] == "202 MB"
    assert "environment_skipped" not in data
    assert not any("fan" in error for error in data["errors"])


def test_health_summary_says_why_fan_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The 0.3.1 deployment: allowlist with only the incomplete 'show system fan'."""
    from netmiko_mcp_linksys.toolkit import prepare_runtime

    commands = tmp_path / "commands.yml"
    commands.write_text(
        "allowed_commands:\n  - show system information\n  - show device temperature\n"
        "  - show system fan\n  - show system utilization\n"
        "denied_commands:\n  - configure*\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("NETMIKO_MCP_COMMAND_FILE", str(commands))
    prepare_runtime()
    try:
        install(
            monkeypatch,
            FakeSwitch(
                {
                    "show system information": s.SYSTEM,
                    "show device temperature": raw("show-device-temperature.txt"),
                    "show system utilization": raw("show-system-utilization.txt"),
                }
            ),
        )
        data = json.loads(r.health_summary())
        assert "fan" not in data["environment"]
        assert data["environment_skipped"] == {
            "fan": "'show system fan status' is not on the allowlist (commands.yml)"
        }
    finally:
        from tests.conftest import COMMANDS

        monkeypatch.setenv("NETMIKO_MCP_COMMAND_FILE", str(COMMANDS))
        prepare_runtime()


def test_example_allowlist_has_the_complete_fan_show(commands_file: Path) -> None:
    text = commands_file.read_text(encoding="utf-8")
    assert "  - show system fan status\n" in text
    assert "  - show system fan\n" not in text


# --------------------------------------------------- 5: Gi port prefixes


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("Gi0/15", "0/15"),
        ("gi0/15", "0/15"),
        ("GI 0/15", "0/15"),
        ("GigabitEthernet0/15", "0/15"),
        ("gigabitethernet 0/1", "0/1"),
        ("ge0/28", "0/28"),
        ("0/15", "0/15"),
    ],
)
def test_validate_port_accepts_interface_prefix(given: str, expected: str) -> None:
    assert canonical_port(given) == expected
    assert validate_port(given) == expected


def test_canonical_port_leaves_other_values_alone() -> None:
    assert canonical_port(514) == 514
    assert canonical_port(None) is None
    assert canonical_port("Gi1/0/15") == "Gi1/0/15"
    with pytest.raises(ValidationError):
        validate_port("Gi0/29")


def test_port_counters_with_gi_prefix_live_output(
    monkeypatch: pytest.MonkeyPatch, reset_command_file: None
) -> None:
    install(monkeypatch, FakeSwitch({"show interfaces counters": raw("show-interfaces-counters.txt")}))
    for port in ("Gi0/15", "0/15"):
        data = json.loads(r.port_counters(port=port))
        assert list(data["counters"]) == ["0/15"]
        counters = data["counters"]["0/15"]
        assert (counters["indiscard"], counters["inerrs"], counters["outdiscard"]) == (115, 21, 4)
    data = json.loads(call("port_counters", {"port": "Gi0/15"}))
    assert list(data["counters"]) == ["0/15"] and data["parse_warnings"] == []


def test_protected_and_caution_ports_still_apply_with_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SWITCH_PROTECTED_PORTS", "0/10,0/24")
    monkeypatch.setenv("SWITCH_CAUTION_PORTS", "0/15")
    for port in ("Gi0/10", "gi 0/24", "GigabitEthernet0/10"):
        with pytest.raises(ValidationError, match="protected port 0/"):
            reject_protected_port(port, action="port_disable")
    with pytest.raises(ValidationError, match="caution port"):
        require_caution_confirmation("Gi0/15", confirmed=False, action="port_disable")
    assert require_caution_confirmation("Gi0/15", confirmed=True, action="port_disable")


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("port_disable", {"port": "Gi0/10"}),
        ("port_disable", {"port": "gi0/24", "dry_run": False}),
        ("poe_disable", {"port": "Gi0/10"}),
        ("poe_cycle", {"port": "GigabitEthernet0/10"}),
        ("port_set_description", {"port": "Gi0/24", "text": "x"}),
        ("port_set_description", {"port": "Gi0/24", "text": "x", "dry_run": False}),
        ("storm_control_set", {"port": "Gi0/10", "storm_type": "broadcast", "level_pps": 100}),
    ],
)
def test_mcp_write_tools_refuse_protected_ports_with_prefix(
    monkeypatch: pytest.MonkeyPatch, tool: str, arguments: dict[str, Any]
) -> None:
    monkeypatch.setenv("SWITCH_PROTECTED_PORTS", "0/10,0/24")
    switch = install(monkeypatch, FakeSwitch({}))
    text = call(tool, arguments)
    assert text.startswith("Rejected: Refusing"), text
    assert "protected port 0/" in text
    assert switch.config_sets == [] and switch.sessions == 0


def test_mcp_caution_port_with_prefix_needs_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_PROTECTED_PORTS", "0/10,0/24")
    monkeypatch.setenv("SWITCH_CAUTION_PORTS", "0/15")
    switch = install(monkeypatch, FakeSwitch({}))
    text = call("port_disable", {"port": "Gi0/15", "dry_run": False})
    assert text.startswith("Rejected:") and "caution port" in text
    assert switch.config_sets == []


def test_every_switch_port_tool_is_normalised_centrally() -> None:
    names = {f.__name__ for f in server.ALL_TOOLS if server._takes_switch_port(f)}
    assert "syslog_set" not in names  # its port is the UDP port
    assert {"port_counters", "counters_delta", "mac_table", "port_disable", "poe_cycle",
            "port_set_description", "clear_counters", "cable_diag"} <= names

    seen: list[Any] = []

    def sample(port: str | None = None, dry_run: bool = True) -> str:
        seen.append(port)
        return "ok"

    wrapped = server.tool_entry(sample)
    wrapped(port="Gi0/7")
    wrapped(port=None)
    assert seen == ["0/7", None]


# ---------------------------------------- 1 + 2: call budget, session hang


class SilentChannel:
    """Echoes the command, then never shows a prompt (the 'show users' hang)."""

    RETURN = "\n"
    base_prompt = "LGS328PC"

    def __init__(self, stream: bool = False) -> None:
        self.stream = stream
        self.sent = False
        self.paramiko_cleanup = MagicMock()
        self.disconnect = MagicMock()

    def clear_buffer(self) -> None:
        pass

    def write_channel(self, data: str) -> None:
        self.sent = True

    def read_channel(self) -> str:
        if self.stream:
            time.sleep(0.01)
            return "Gi0/1   up   still streaming\r\n"  # endless output, no prompt
        return ""


class PromptChannel(SilentChannel):
    def __init__(self, text: str) -> None:
        super().__init__()
        self.queue: list[str] = []
        self.text = text

    def write_channel(self, data: str) -> None:
        self.queue = [f"{data}", f"{self.text}\r\n", "LGS328PC#"]

    def read_channel(self) -> str:
        return self.queue.pop(0) if self.queue else ""


def test_call_budget_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SWITCH_CALL_BUDGET", raising=False)
    assert call_budget() == 45.0
    monkeypatch.setenv("SWITCH_CALL_BUDGET", "30")
    assert call_budget() == 30.0
    for bad in ("x", "1", "9999"):
        monkeypatch.setenv("SWITCH_CALL_BUDGET", bad)
        with pytest.raises(ValidationError, match="SWITCH_CALL_BUDGET"):
            call_budget()


@pytest.mark.parametrize("stream", [False, True])
def test_send_paged_stops_at_the_call_budget(stream: bool) -> None:
    """Idle timeout 60 s, but the call budget ends the read after ~0.5 s,
    also when the device keeps sending lines (the idle timer never fires)."""
    chan = SilentChannel(stream=stream)
    started = time.monotonic()
    with call_deadline(0.5), pytest.raises(SwitchConnectionError, match="call budget"):
        send_paged(chan, "show users", timeout=60)
    assert time.monotonic() - started < 3


def test_send_paged_does_not_start_when_budget_is_gone() -> None:
    chan = SilentChannel()
    with call_deadline(0.0), pytest.raises(SwitchConnectionError, match="not sent"):
        send_paged(chan, "show clock")
    assert chan.sent is False


def test_connect_params_read_timeout_follows_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_READ_TIMEOUT", "60")
    assert connect_params()["read_timeout_override"] == 60.0
    with call_deadline(10):
        assert connect_params()["read_timeout_override"] <= 10


def test_failed_session_is_discarded_and_lock_released() -> None:
    chan = SilentChannel()
    order: list[str] = []
    chan.paramiko_cleanup.side_effect = lambda: order.append("transport")
    chan.disconnect.side_effect = lambda: order.append("disconnect")
    with (
        patch("netmiko_mcp_linksys.connection.ConnectHandler", return_value=chan),
        call_deadline(0.3),
        pytest.raises(SwitchConnectionError, match="call budget"),
    ):
        run_show("show users")
    assert order == ["transport", "disconnect"]  # transport closed first
    assert not connection._LOCK.locked()


def test_caught_timeout_still_discards_the_session() -> None:
    """run_show_sequence catches the timeout and returns normally; the
    wedged channel must still not get the graceful logout (which waits for
    a prompt)."""
    chan = SilentChannel()
    with (
        patch("netmiko_mcp_linksys.connection.ConnectHandler", return_value=chan),
        call_deadline(0.3),
    ):
        results = connection.run_show_sequence(["show users", "show clock"])
    assert "call budget" in (results[0][2] or "")
    assert results[1][2] == connection.SEQUENCE_SKIPPED
    chan.paramiko_cleanup.assert_called_once()
    assert not connection._LOCK.locked()


def test_clean_session_logs_out_without_abort() -> None:
    chan = PromptChannel("12:00:00")
    writes: list[str] = []
    original = chan.write_channel

    def record(data: str) -> None:
        writes.append(data)
        original(data)

    chan.write_channel = record  # type: ignore[method-assign]
    with patch("netmiko_mcp_linksys.connection.ConnectHandler", return_value=chan):
        assert run_show("show clock") == "12:00:00"
    assert "\x03" not in writes
    assert writes[-1] == "exit\n"
    chan.disconnect.assert_called_once()


def test_busy_lock_fails_fast_instead_of_queueing() -> None:
    assert connection._LOCK.acquire(timeout=1)
    try:
        started = time.monotonic()
        with (
            call_deadline(0.5),
            pytest.raises(SwitchConnectionError, match="busy"),
            session(),
        ):
            pass
        assert time.monotonic() - started < 2
    finally:
        connection._LOCK.release()


def test_hang_does_not_block_the_next_call() -> None:
    """Retest 0.3.1 repro: 'show users' hangs, then 'show clock' must still
    work (before 0.3.2 it queued behind the hung call and timed out too)."""
    channels = iter([SilentChannel(), PromptChannel("12:00:00")])
    results: dict[str, Any] = {}

    def first() -> None:
        try:
            with call_deadline(1.0):
                run_show("show users")
        except SwitchConnectionError as exc:
            results["first"] = str(exc)

    with patch("netmiko_mcp_linksys.connection.ConnectHandler", side_effect=lambda **_: next(channels)):
        worker = threading.Thread(target=first)
        worker.start()
        time.sleep(0.2)
        started = time.monotonic()
        with call_deadline(5.0):
            results["second"] = run_show("show clock")
        waited = time.monotonic() - started
        worker.join(5)
    assert "call budget" in results["first"]
    assert results["second"] == "12:00:00"
    assert waited < 3


def test_applying_writes_are_not_cut_by_the_budget() -> None:
    budgets: list[float | None] = []

    def sample_write(port: str, dry_run: bool = True) -> str:
        budgets.append(remaining_budget())
        return "ok"

    wrapped = server.tool_entry(sample_write)
    wrapped(port="0/3")
    wrapped(port="0/3", dry_run=True)
    wrapped(port="0/3", dry_run=False)
    assert budgets[0] is not None and budgets[1] is not None
    assert budgets[2] is None


def test_invalid_budget_setting_is_a_tool_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_CALL_BUDGET", "abc")
    wrapped = server.tool_entry(lambda: "ok")
    assert wrapped().startswith("Error: SWITCH_CALL_BUDGET")


# ------------------------------------------- 1: running-config in background


def _slow(text: str, seconds: float) -> Any:
    def answer() -> str:
        time.sleep(seconds)
        return text

    return answer


def test_config_read_pending_then_picked_up(monkeypatch: pytest.MonkeyPatch) -> None:
    switch = install(
        monkeypatch,
        FakeSwitch({"show current running-config": _slow(RUNNING_CONFIG, 1.0),
                    "show system information": s.SYSTEM}),
    )
    started = time.monotonic()
    with call_deadline(2.5):  # waits 0.5 s (2 s answer margin)
        first = r.config_read()
    assert first.startswith("Pending: running-config dump still in progress")
    assert time.monotonic() - started < 2.0
    time.sleep(1.2)
    with call_deadline(2.5):
        data = json.loads(r.config_read())
    assert data["lines"] > 5 and "OldSecretComm77" not in data["config"]
    assert data["read_at"] and data["dump_seconds"] >= 0.9
    assert switch.shows.count("show current running-config") == 1  # picked up, not re-read


def test_config_dump_is_not_reused_after_delivery(monkeypatch: pytest.MonkeyPatch) -> None:
    switch = install(monkeypatch, FakeSwitch({"show current running-config": RUNNING_CONFIG}))
    with call_deadline(5):
        json.loads(r.config_read())
        json.loads(r.config_backup())
    assert switch.shows.count("show current running-config") == 2


def test_config_dump_from_before_a_change_is_dropped(monkeypatch: pytest.MonkeyPatch) -> None:
    switch = install(
        monkeypatch, FakeSwitch({"show current running-config": _slow(RUNNING_CONFIG, 0.5)})
    )
    with call_deadline(2.2):
        assert r.config_read().startswith("Pending:")
    time.sleep(0.8)
    connection._bump_config_generation()  # a write through this server
    with call_deadline(5):
        json.loads(r.config_read())
    assert switch.shows.count("show current running-config") == 2


def test_config_dump_error_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    install(monkeypatch, FakeSwitch({"show current running-config": "% Invalid input detected"}))
    with call_deadline(5):
        result = r.config_read()
    assert result.startswith("Error: show current running-config is not available")


def test_config_dump_has_its_own_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_CONFIG_DUMP_TIMEOUT", "5")
    with call_deadline(5), pytest.raises(ValidationError, match="SWITCH_CONFIG_DUMP_TIMEOUT"):
        configdump.running_config()
    monkeypatch.setenv("SWITCH_CONFIG_DUMP_TIMEOUT", "120")
    assert configdump.dump_timeout() == 120


# --------------------------------------------- 6: audit unfinished / duration


def _records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_budget_error_is_audited_with_duration(
    audit_log: Path, monkeypatch: pytest.MonkeyPatch, reset_command_file: None
) -> None:
    def hanging_show(command: str) -> str:
        with call_deadline():  # nested: keeps the tool's deadline
            assert remaining_budget() is not None
            raise SwitchConnectionError(f"Gave up on {command!r}: call budget used up")

    monkeypatch.setattr(server, "run_show", hanging_show)
    text = call("show", {"command": "show users"})
    assert text.startswith("Error: Gave up on 'show users'")
    start, result = _records(audit_log)
    assert start["phase"] == "start" and result["call_id"] == start["call_id"]
    assert result["result"].startswith("Error: Gave up")
    assert isinstance(result["duration_ms"], int)


def test_audit_tail_unfinished_has_age(audit_log: Path) -> None:
    from datetime import UTC, datetime, timedelta

    started = (datetime.now(UTC) - timedelta(seconds=90)).isoformat()
    lines = [
        {"time": started, "tool": "config_read", "phase": "start", "call_id": "c1"},
        {"time": started, "tool": "show", "phase": "start", "call_id": "c2"},
        {"time": started, "tool": "show", "params": {}, "allowed": True,
         "result": "Error: Gave up", "call_id": "c2", "duration_ms": 45012},
    ]
    audit_log.write_text("".join(json.dumps(line) + "\n" for line in lines), encoding="utf-8")
    entries = json.loads(r.audit_tail(10))["entries"]
    unfinished, finished = entries[0], entries[1]
    assert unfinished["call_id"] == "c1" and unfinished["result"].startswith("unfinished")
    assert 89_000 <= unfinished["age_ms"] < 200_000
    assert finished["duration_ms"] == 45012 and "age_ms" not in finished
