"""0.3.2: SSH session handling after the retest hang (fakes only, never a device).

Covers: abort and logout after a timeout, the hard-close fallback when the
logout hangs, the reconnect cooldown, one session at a time (also for the
background config dump), idle close, graceful shutdown and the netmiko
connect leak.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any, ClassVar
from unittest.mock import patch

import pytest

from lgs_switch_mcp import configdump, connection
from lgs_switch_mcp.connection import (
    SwitchConnectionError,
    call_deadline,
    run_show,
    send_paged,
    session,
)
from lgs_switch_mcp.validation import ValidationError

PROMPT = "LGS328PC#"


class _Transport:
    def __init__(self, conn: FakeConn) -> None:
        self.conn = conn

    def is_active(self) -> bool:
        return not self.conn.closed

    def close(self) -> None:
        self.conn.closed = True
        self.conn.transport_closed += 1


class _Channel:
    def __init__(self, conn: FakeConn) -> None:
        self.conn = conn
        self.transport = _Transport(conn)

    @property
    def closed(self) -> bool:
        return self.conn.closed


class FakeConn:
    """A netmiko-like connection that records everything written.

    hang:          'show users' prints nothing and never shows a prompt.
    exit_closes:   'exit' makes the switch close the channel.
    fail_open:     _open() raises after the transport was authenticated.
    """

    RETURN = "\n"
    base_prompt = "LGS328PC"
    opened: ClassVar[list[FakeConn]] = []

    def __init__(
        self, *, hang: bool = False, exit_closes: bool = True, fail_open: bool = False
    ) -> None:
        self.hang = hang
        self.exit_closes = exit_closes
        self.fail_open = fail_open
        self.closed = False
        self.transport_closed = 0
        self.writes: list[str] = []
        self.queue: list[str] = []
        self.disconnects = 0
        self.cleanups = 0
        self.remote_conn = _Channel(self)
        self.remote_conn_pre = self.remote_conn.transport
        self.read_timeout_override: float | None = None

    def _open(self) -> None:
        FakeConn.opened.append(self)
        if self.fail_open:
            raise TimeoutError("Timed out opening the shell channel")

    def clear_buffer(self) -> None:
        self.queue.clear()

    def write_channel(self, data: str) -> None:
        if self.closed:
            raise OSError("Socket is closed")
        self.writes.append(data)
        command = data.strip()
        if command == "exit":
            if self.exit_closes:
                self.closed = True
            return
        if data == "\x03":
            self.hang = False
            self.queue.append(f"^C\r\n{PROMPT}")
            return
        if command in ("", "\x15") or self.hang:
            return
        self.queue += [data, f"output of {command}\r\n", PROMPT]

    def read_channel(self) -> str:
        if self.closed:
            raise OSError("Socket is closed")
        return self.queue.pop(0) if self.queue else ""

    def paramiko_cleanup(self) -> None:
        self.cleanups += 1
        self.remote_conn_pre.close()

    def disconnect(self) -> None:
        self.disconnects += 1
        self.paramiko_cleanup()


@pytest.fixture(autouse=True)
def _fresh(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeConn.opened = []
    monkeypatch.setenv("SWITCH_SESSION_IDLE", "0")
    monkeypatch.setenv("SWITCH_COOLDOWN_BASE", "0")
    monkeypatch.setenv("SWITCH_LOGOUT_TIMEOUT", "0.5")
    monkeypatch.setenv("SWITCH_PAGING_OFF", "0")


def connects(*conns: FakeConn) -> Any:
    queue = list(conns)

    def factory(**params: Any) -> FakeConn:
        assert params.get("auto_connect") is False
        return queue.pop(0)

    return patch("lgs_switch_mcp.connection.ConnectHandler", side_effect=factory)


# --------------------------------------------- clean logout after a timeout


def test_timeout_aborts_then_logs_out_then_closes() -> None:
    conn = FakeConn(hang=True)
    with (
        connects(conn),
        pytest.raises(SwitchConnectionError, match="call budget"),
        call_deadline(0.5),
    ):
        run_show("show users")
    # Ctrl-C first, then the logout; the channel ends closed.
    ctrl_c = conn.writes.index("\x03")
    assert conn.writes.index("exit\n") > ctrl_c
    assert conn.writes[0].startswith("show users")
    assert conn.closed and conn.cleanups >= 1
    assert not connection._LOCK.locked()
    assert connection._held is None


def test_abort_quits_a_pager_and_leaves_config_mode() -> None:
    conn = FakeConn()

    def write(data: str) -> None:
        conn.writes.append(data)
        if data == "\x03":
            conn.queue.append("--More-- ")
        elif data == "q":
            conn.queue.append("LGS328PC(config-if)#")
        elif data.strip() == "exit":
            conn.closed = True

    conn.write_channel = write  # type: ignore[method-assign]
    connection._close(conn, abort=True)
    assert "q" in conn.writes
    assert conn.writes[-2:] == ["end\n", "exit\n"]
    assert conn.closed


def test_clean_call_logs_out_without_abort() -> None:
    conn = FakeConn()
    with connects(conn):
        assert run_show("show clock") == "output of show clock"
    assert "\x03" not in conn.writes
    assert conn.writes[-1] == "exit\n"
    assert conn.closed


# ------------------------------------------- fallback when the logout hangs


def test_hanging_logout_falls_back_to_hard_close(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_LOGOUT_TIMEOUT", "0.5")
    conn = FakeConn(hang=True, exit_closes=False)
    conn.write_channel_orig = conn.write_channel  # type: ignore[attr-defined]

    def stuck(data: str) -> None:  # Ctrl-C does not help either
        conn.writes.append(data)

    conn.write_channel = stuck  # type: ignore[method-assign]
    started = time.monotonic()
    connection._close(conn, abort=True)
    elapsed = time.monotonic() - started
    assert "exit\n" in conn.writes
    assert conn.closed and conn.transport_closed >= 1
    # abort drain (2 s) + logout timeout (0.5 s), never the 60 s netmiko default
    assert elapsed < connection.ABORT_DRAIN_SECONDS + 0.5 + 1.5


def test_logout_errors_still_close_the_transport() -> None:
    conn = FakeConn()

    def broken(data: str) -> None:
        raise OSError("Socket exception: broken pipe")

    conn.write_channel = broken  # type: ignore[method-assign]
    connection._close(conn, abort=True)
    assert conn.closed and conn.cleanups >= 1


def test_logout_timeout_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SWITCH_LOGOUT_TIMEOUT")
    assert connection.logout_timeout() == 3.0
    monkeypatch.setenv("SWITCH_LOGOUT_TIMEOUT", "99")
    with pytest.raises(ValidationError, match="SWITCH_LOGOUT_TIMEOUT"):
        connection.logout_timeout()


# ----------------------------------------------------------- backoff / breaker


def test_timeout_opens_the_cooldown_without_new_connect(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_COOLDOWN_BASE", "30")
    with (
        connects(FakeConn(hang=True)),
        pytest.raises(SwitchConnectionError, match="call budget"),
        call_deadline(0.5),
    ):
        run_show("show users")
    assert len(FakeConn.opened) == 1
    with connects(FakeConn()), pytest.raises(SwitchConnectionError) as excinfo:
        run_show("show clock")
    message = str(excinfo.value)
    assert "cooling down" in message and "retry in" in message
    assert "No SSH connection was opened" in message
    assert len(FakeConn.opened) == 1  # no second login


def test_cooldown_doubles_and_is_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_COOLDOWN_BASE", "30")
    monkeypatch.setenv("SWITCH_COOLDOWN_MAX", "100")
    breaker = connection._BREAKER
    lengths = []
    for _ in range(4):
        before = time.time()
        breaker.failure("a command timeout")
        lengths.append(round(breaker.until - before))
    assert lengths == [30, 60, 100, 100]
    breaker.success()
    assert breaker.failures == 0 and breaker.until == 0.0


def test_after_the_cooldown_one_attempt_and_success_resets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SWITCH_COOLDOWN_BASE", "30")
    connection._BREAKER.failure("a failed or slow SSH connect")
    connection._BREAKER.until = time.time() - 1  # cooldown over
    with connects(FakeConn()):
        assert run_show("show clock") == "output of show clock"
    assert connection._BREAKER.failures == 0


def test_failed_connect_is_closed_and_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    """netmiko leaks the authenticated transport when invoke_shell fails in
    its constructor; with auto_connect=False we keep the reference and close it."""
    monkeypatch.setenv("SWITCH_COOLDOWN_BASE", "30")
    conn = FakeConn(fail_open=True)
    with connects(conn), pytest.raises(SwitchConnectionError):
        run_show("show clock")
    assert conn.transport_closed >= 1 and conn.closed
    assert connection._BREAKER.failures == 1
    with pytest.raises(SwitchConnectionError, match="cooling down"):
        run_show("show clock")


def test_cooldown_survives_a_restart(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_COOLDOWN_BASE", "30")
    connection._BREAKER.failure("a command timeout")
    connection._BREAKER.reset()  # new process: memory empty, state file kept
    with pytest.raises(SwitchConnectionError, match="cooling down"):
        run_show("show clock")
    assert FakeConn.opened == []


def test_cooldown_off_with_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_COOLDOWN_BASE", "0")
    connection._BREAKER.failure("a command timeout")
    with connects(FakeConn()):
        assert run_show("show clock") == "output of show clock"


def test_validation_errors_do_not_open_the_cooldown(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_COOLDOWN_BASE", "30")
    with connects(FakeConn()), pytest.raises(ValidationError), session():
        raise ValidationError("bad port")
    assert connection._BREAKER.failures == 0


def test_poe_restore_may_bypass_the_cooldown(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_COOLDOWN_BASE", "30")
    connection._BREAKER.failure("a command timeout")
    with connects(FakeConn()):
        result = connection.run_in_session(lambda c: "on", bypass_cooldown=True)
    assert result == "on"


def test_no_automatic_retry_after_a_failure() -> None:
    with connects(FakeConn(fail_open=True), FakeConn()), pytest.raises(SwitchConnectionError):
        run_show("show clock")
    assert len(FakeConn.opened) == 1


# ------------------------------------------------------ one session at most


def test_no_parallel_session(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_CALL_BUDGET", "10")
    active = 0
    peak = 0
    guard = threading.Lock()

    class Counting(FakeConn):
        def _open(self) -> None:
            nonlocal active, peak
            super()._open()
            with guard:
                active += 1
                peak = max(peak, active)

        def paramiko_cleanup(self) -> None:
            nonlocal active
            if not getattr(self, "counted_closed", False):
                self.counted_closed = True
                with guard:
                    active -= 1
            super().paramiko_cleanup()

    conns = [Counting() for _ in range(6)]
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            with call_deadline(10):
                run_show("show clock")
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    with connects(*conns):
        threads = [threading.Thread(target=worker) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(15)
    assert errors == []
    assert peak == 1


def test_config_dump_uses_the_same_single_session(monkeypatch: pytest.MonkeyPatch) -> None:
    """The background dump must wait for the session lock, not open a second login."""
    seen: list[bool] = []

    def fake_read(conn: Any) -> Any:
        seen.append(connection._LOCK.locked())
        return "hostname x", {}

    monkeypatch.setattr(configdump, "_read", fake_read)
    conn = FakeConn()
    with connects(conn):
        assert connection._LOCK.acquire(timeout=1)
        try:
            with call_deadline(2.4), pytest.raises(configdump.ConfigDumpPending):
                configdump.running_config()
            assert FakeConn.opened == []  # blocked behind the lock, no second session
        finally:
            connection._LOCK.release()
        for _ in range(100):
            if seen and conn.closed:
                break
            time.sleep(0.05)
    assert seen == [True]
    assert FakeConn.opened == [conn] and conn.closed


# -------------------------------------------------------------- idle close


def test_session_is_reused_then_closed_when_idle(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_SESSION_IDLE", "0.3")
    conn = FakeConn()
    with connects(conn):
        assert run_show("show clock") == "output of show clock"
        assert run_show("show version") == "output of show version"
    assert FakeConn.opened == [conn]  # one login for both calls
    assert not conn.closed and connection._held is not None
    for _ in range(40):
        if conn.closed:
            break
        time.sleep(0.05)
    assert conn.closed and conn.writes[-1] == "exit\n"
    assert connection._held is None


def test_dead_kept_session_is_replaced_without_io(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_SESSION_IDLE", "30")
    first, second = FakeConn(), FakeConn()
    with connects(first, second):
        run_show("show clock")
        first.closed = True  # switch dropped it while idle
        assert run_show("show clock") == "output of show clock"
    assert FakeConn.opened == [first, second]
    connection.shutdown()
    assert second.closed


def test_session_log_setting_change_opens_a_new_session(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_SESSION_IDLE", "30")
    first, second = FakeConn(), FakeConn()
    with connects(first, second):
        connection.run_in_session(lambda c: None, enable_session_log=True)
        connection.run_in_session(lambda c: None, enable_session_log=False)
    assert first.closed and first.writes[-1] == "exit\n"
    connection.shutdown()
    assert second.closed


def test_timed_out_session_is_never_kept(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_SESSION_IDLE", "30")
    conn = FakeConn(hang=True)
    with (
        connects(conn),
        pytest.raises(SwitchConnectionError),
        call_deadline(0.5),
        session() as c,
    ):
        send_paged(c, "show users", timeout=60)
    assert connection._held is None and conn.closed


def test_session_idle_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SWITCH_SESSION_IDLE")
    assert connection.session_idle() == 10.0
    monkeypatch.setenv("SWITCH_SESSION_IDLE", "-1")
    with pytest.raises(ValidationError, match="SWITCH_SESSION_IDLE"):
        connection.session_idle()


# --------------------------------------------------------- graceful shutdown


def test_shutdown_logs_out_the_kept_session(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_SESSION_IDLE", "60")
    conn = FakeConn()
    with connects(conn):
        run_show("show clock")
    assert not conn.closed
    connection.shutdown()
    assert conn.closed and conn.writes[-1] == "exit\n"
    connection.shutdown()  # idempotent


def test_shutdown_hard_closes_a_session_in_use() -> None:
    conn = FakeConn(hang=True)
    started = threading.Event()

    def hold() -> None:
        with connects(conn), session():
            started.set()
            time.sleep(1.5)

    t = threading.Thread(target=hold)
    t.start()
    assert started.wait(2)
    connection.shutdown(timeout=0.2)
    assert conn.transport_closed >= 1
    t.join(5)


def test_main_registers_shutdown(monkeypatch: pytest.MonkeyPatch) -> None:
    from lgs_switch_mcp import server

    calls: list[str] = []
    monkeypatch.setattr(server, "prepare_runtime", lambda: None)
    monkeypatch.setattr(server, "startup_checks", lambda: None)
    monkeypatch.setattr(server.mcp, "run", lambda **kw: calls.append("run"))
    monkeypatch.setattr(server.connection, "shutdown", lambda *a, **k: calls.append("shutdown"))
    monkeypatch.setattr(server, "_install_signal_handlers", lambda: calls.append("signals"))
    server.main()
    assert calls == ["signals", "run", "shutdown"]


def test_breaker_state_file_is_plain_json(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_COOLDOWN_BASE", "30")
    connection._BREAKER.failure("a command timeout")
    from lgs_switch_mcp import configstore

    data = configstore.read_state(connection.BREAKER_STATE)
    assert data["failures"] == 1 and data["reason"] == "a command timeout"
    json.dumps(data)
    connection._BREAKER.success()
    assert not configstore.read_state(connection.BREAKER_STATE)
