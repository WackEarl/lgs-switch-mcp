"""SSH session handling, pager handling, and CLI sequence runners.

No connection is opened at import or process start. Each tool call opens one
session (port_overview included), holds a process-wide lock for the duration,
and disconnects after.

Parser helpers live in ``parser``, command builders in ``commands``, and
``SwitchConnectionError`` in ``errors``. This module remains the session
layer and the public import path.
"""

from __future__ import annotations

import math
import os
import re
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from netmiko import ConnectHandler

from lgs_switch_mcp.commands import (
    READBACK_DESCRIPTION,
    READBACK_INTERFACE,
    READBACK_POE,
    build_admin_state_commands,
    build_description_commands,
    build_poe_commands,
)
from lgs_switch_mcp.errors import SwitchConnectionError, wrap_transport_error
from lgs_switch_mcp.parser import (
    MAX_PAGES,
    PAGE_BREAK,
    PAGER_RE,
    clean_output,
    prompt_end_regex,
    prompt_prefix,
    prompt_regex,
    visible_tail,
)
from lgs_switch_mcp.redaction import redact_device_text, redact_sensitive_lines
from lgs_switch_mcp.snmp_cli import (
    redact_community_listing,
    redact_community_name_fields,
)
from lgs_switch_mcp.validation import (
    ValidationError,
    config_output_is_error,
    redact_secrets,
)

# Backward-compatible alias; new code should use SwitchConnectionError.
ConnectionError = SwitchConnectionError

_LOCK = threading.Lock()

DEFAULT_READ_TIMEOUT = 60.0
MAX_READ_TIMEOUT = 600.0

# Wall-clock budget of one tool call (lock wait, connect, every command).
# MCP clients give up after 60 s by default (MCP error -32001, raised on the
# caller's side; the hub's own MCP_CALL_TIMEOUT_MS defaults to 300 s). A
# call that runs on after the caller gave up keeps the session lock, so
# every later call queues behind it (retest 0.3.1: "show users" hang).
# The budget makes such a call end as a tool error well before that.
DEFAULT_CALL_BUDGET = 45.0
MIN_CALL_BUDGET = 5.0
MAX_CALL_BUDGET = 600.0

# Absolute deadline (time.monotonic()) of the current tool call, if any.
_DEADLINE: ContextVar[float | None] = ContextVar("switch_call_deadline", default=None)

# Bumped by every configuration set and save, so a cached running-config
# dump from before a change is never served after it.
_config_generation = 0
_generation_lock = threading.Lock()

# Best-effort paging-off for the Aricent/ISS-based LGS CLI. On ISS-family
# firmware this is a Global Configuration command (it is rejected in
# privileged exec, which is what the 0.1.0 live test hit). The result is not
# trusted: the pager loop below handles paging either way.
PAGING_OFF_CONFIG = ("set cli pagination off",)

# Y/N confirmation at the end of the last visible line, e.g. "(y/n)",
# "[Y/N]:", "(yes/no)?". The LGS328PC save prompt text is NOT live-confirmed
# (issue #4). Only this shape is answered, and only once; anything else
# runs into the idle timeout and fails without an answer (fail-closed).
SAVE_CONFIRM_RE = re.compile(
    r"(?:\(\s*y(?:es)?\s*/\s*n(?:o)?\s*\)|\[\s*y(?:es)?\s*/\s*n(?:o)?\s*\])\s*[:?]?\s*$",
    re.IGNORECASE,
)
SAVE_CONFIRM_ANSWER = "y"

_warned: set[str] = set()


def warn(message: str, *, once_key: str | None = None) -> None:
    """Write a redacted warning to stderr (stdout is the MCP channel)."""
    if once_key is not None:
        if once_key in _warned:
            return
        _warned.add(once_key)
    print(f"lgs-switch-mcp: warning: {redact_secrets(message)}", file=sys.stderr, flush=True)


def read_timeout() -> float:
    raw = (os.environ.get("SWITCH_READ_TIMEOUT") or "").strip()
    if not raw:
        return DEFAULT_READ_TIMEOUT
    try:
        value = float(raw)
    except ValueError:
        raise ValidationError(
            f"SWITCH_READ_TIMEOUT must be a number of seconds, got {raw!r}."
        ) from None
    if not 1 <= value <= MAX_READ_TIMEOUT:
        raise ValidationError(
            f"SWITCH_READ_TIMEOUT must be between 1 and {int(MAX_READ_TIMEOUT)} seconds."
        )
    return value


def call_budget() -> float:
    """SWITCH_CALL_BUDGET in seconds (default 45, range 5-600)."""
    raw = (os.environ.get("SWITCH_CALL_BUDGET") or "").strip()
    if not raw:
        return DEFAULT_CALL_BUDGET
    try:
        value = float(raw)
    except ValueError:
        raise ValidationError(
            f"SWITCH_CALL_BUDGET must be a number of seconds, got {raw!r}."
        ) from None
    if not MIN_CALL_BUDGET <= value <= MAX_CALL_BUDGET:
        raise ValidationError(
            f"SWITCH_CALL_BUDGET must be between {int(MIN_CALL_BUDGET)} and "
            f"{int(MAX_CALL_BUDGET)} seconds."
        )
    return value


@contextmanager
def call_deadline(seconds: float | None = None) -> Iterator[float]:
    """Bound everything the current call does on the switch.

    Sets an absolute deadline ``seconds`` (default: SWITCH_CALL_BUDGET)
    from now. Nested use keeps the outer deadline. send_paged, send_help
    and the session lock honour it; when it runs out the call ends with a
    SwitchConnectionError instead of outliving the caller.
    """
    current = _DEADLINE.get()
    if current is not None:
        yield current
        return
    deadline = time.monotonic() + (call_budget() if seconds is None else seconds)
    token = _DEADLINE.set(deadline)
    try:
        yield deadline
    finally:
        _DEADLINE.reset(token)


def remaining_budget() -> float | None:
    """Seconds left in the current call's budget, or None without a deadline."""
    deadline = _DEADLINE.get()
    return None if deadline is None else deadline - time.monotonic()


def config_generation() -> int:
    return _config_generation


def _bump_config_generation() -> None:
    global _config_generation
    with _generation_lock:
        _config_generation += 1


def paging_off_enabled() -> bool:
    raw = (os.environ.get("SWITCH_PAGING_OFF") or "1").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def prepare_private_file(path_str: str) -> Path:
    """Create (if needed) an append-only file with mode 0600, or raise OSError."""
    path = Path(path_str).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    created = not path.exists()
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        if created:
            os.chmod(path, 0o600)
    finally:
        os.close(fd)
    return path


def session_log_path() -> str | None:
    """Return a writable SWITCH_SESSION_LOG path, or None (never raises)."""
    raw = (os.environ.get("SWITCH_SESSION_LOG") or "").strip()
    if not raw:
        return None
    try:
        return str(prepare_private_file(raw))
    except OSError as exc:
        warn(
            f"SWITCH_SESSION_LOG {raw} is not writable ({exc}); session log disabled.",
            once_key=f"session-log:{raw}",
        )
        return None


def _commands_include_snmp_community(commands: list[str]) -> bool:
    return any(re.search(r"(?i)\bsnmp\s+community\b", command) for command in commands)


# Whitespace normalization matches the show-tool command filter
# (" ".join(command.split())). "sh" is the shortest show prefix; kind
# prefixes start at 2 characters so "co"/"vi"/"us" are fail-closed without
# also matching unrelated tokens such as "group".
_MIN_SHOW_PREFIX = 2
_MIN_SENSITIVE_KIND_PREFIX = 2
_SENSITIVE_SNMP_KINDS = ("community", "viewtree", "user")


def _normalized_command_words(command: str) -> list[str]:
    """Collapse ASCII whitespace like validate_command, then lower-case."""
    return " ".join(command.split()).lower().split()


def _is_command_prefix(submitted: str, full: str, *, min_len: int) -> bool:
    return len(submitted) >= min_len and full.startswith(submitted)


def _snmp_sensitive_kind(command: str) -> str | None:
    """Return community/viewtree/user if this is a sensitive SNMP show.

    Accepts abbreviated first and kind words (``sh snmp comm``) by prefix,
    case-insensitively, with any extra trailing words. ``snmp`` itself is
    matched in full.
    """
    words = _normalized_command_words(command)
    if len(words) < 3:
        return None
    show_w, snmp_w, kind = words[0], words[1], words[2]
    if not _is_command_prefix(show_w, "show", min_len=_MIN_SHOW_PREFIX):
        return None
    if snmp_w != "snmp":
        return None
    for full in _SENSITIVE_SNMP_KINDS:
        if _is_command_prefix(kind, full, min_len=_MIN_SENSITIVE_KIND_PREFIX):
            return full
    return None


def _is_snmp_sensitive_show(command: str) -> bool:
    return _snmp_sensitive_kind(command) is not None


def _is_strict_show(command: str) -> bool:
    """``show radius …`` (any abbreviation of show) uses strict line redaction."""
    words = _normalized_command_words(command)
    return (
        len(words) >= 2
        and _is_command_prefix(words[0], "show", min_len=_MIN_SHOW_PREFIX)
        and _is_command_prefix(words[1], "radius", min_len=3)
    )


def redact_show_output(command: str, text: str) -> str:
    """Redact secrets in exec output.

    Community listings are fully masked; every output then goes through the
    fail-closed line rules (``redaction``), strict for ``show radius``.
    """
    if _snmp_sensitive_kind(command) == "community":
        text = redact_community_listing(text)
    else:
        text = redact_secrets(text)
    return redact_sensitive_lines(text, strict=_is_strict_show(command))


def redact_session_log_file() -> None:
    """Rewrite SWITCH_SESSION_LOG so a community echo cannot remain in clear text.

    Called after the netmiko session is disconnected. Failures are
    warnings only; they never raise.
    """
    raw = (os.environ.get("SWITCH_SESSION_LOG") or "").strip()
    if not raw:
        return
    path = Path(raw).expanduser()
    if not path.is_file():
        return
    try:
        original = path.read_text(encoding="utf-8", errors="replace")
        # Do not use listing fail-closed here: a session log is not a
        # show snmp community table and must not be replaced wholesale.
        # Label-regex still masks Community Name fields (including
        # communities that are not the configured secret).
        redacted = redact_sensitive_lines(
            redact_community_name_fields(redact_secrets(original))
        )
        if redacted == original:
            return
        path.write_text(redacted, encoding="utf-8")
        os.chmod(path, 0o600)
    except OSError as exc:
        warn(
            f"SWITCH_SESSION_LOG could not be redacted ({exc}).",
            once_key=f"session-log-redact:{raw}",
        )


def _netmiko_read_timeout() -> float:
    """SWITCH_READ_TIMEOUT, cut to the call budget left (netmiko's own
    reads during connect and config sets cannot outlive the call)."""
    limit = read_timeout()
    left = remaining_budget()
    if left is not None:
        limit = max(1.0, min(limit, left))
    return limit


def connect_params(*, enable_session_log: bool = True) -> dict[str, Any]:
    host = (os.environ.get("SWITCH_HOST") or "").strip()
    username = (os.environ.get("SWITCH_USER") or "").strip()
    password = os.environ.get("SWITCH_PASSWORD") or ""
    device_type = (os.environ.get("SWITCH_DEVICE_TYPE") or "cisco_s300").strip() or "cisco_s300"
    known_hosts = (os.environ.get("SWITCH_KNOWN_HOSTS") or "").strip()

    missing = [
        name
        for name, value in (
            ("SWITCH_HOST", host),
            ("SWITCH_USER", username),
            ("SWITCH_PASSWORD", password),
            ("SWITCH_KNOWN_HOSTS", known_hosts),
        )
        if not value
    ]
    if missing:
        raise ValidationError(
            "Missing required environment variable(s): " + ", ".join(missing)
        )
    if not Path(known_hosts).expanduser().is_file():
        raise ValidationError(
            f"SWITCH_KNOWN_HOSTS file does not exist: {known_hosts}"
        )

    params: dict[str, Any] = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "use_keys": False,
        "allow_agent": False,
        "ssh_strict": True,
        "system_host_keys": False,
        "alt_host_keys": True,
        "alt_key_file": str(Path(known_hosts).expanduser()),
        "conn_timeout": 15,
        "auth_timeout": 20,
        "fast_cli": False,
        "read_timeout_override": _netmiko_read_timeout(),
    }
    log_path = session_log_path() if enable_session_log else None
    if log_path is not None:
        # netmiko masks the password/secret in the session log (no_log), and
        # only channel reads are recorded (record_writes stays False).
        params["session_log"] = log_path
        params["session_log_file_mode"] = "append"
        params["session_log_record_writes"] = False
    return params


def disable_paging_best_effort(conn: Any) -> None:
    """Try the ISS paging-off command; never fail the tool call because of it."""
    if not paging_off_enabled():
        return
    try:
        output = conn.send_config_set(
            list(PAGING_OFF_CONFIG),
            exit_config_mode=True,
            cmd_verify=False,
            read_timeout=read_timeout(),
        )
    except Exception as exc:  # noqa: BLE001 - best effort; never raised to the caller
        warn(f"paging-off sequence failed ({exc}); relying on pager handling.", once_key="paging")
        return
    if config_output_is_error(str(output), commands=list(PAGING_OFF_CONFIG)):
        warn(
            "switch rejected 'set cli pagination off'; relying on pager handling.",
            once_key="paging",
        )


BUSY_MESSAGE = (
    "Switch session busy: another call still holds the SSH session "
    "(waited {waited:g}s). Nothing was sent; try again shortly."
)

# ----------------------------------------------------------- session layer
#
# One SSH session to the switch at most, ever: every user of the switch
# (tool calls, the background config dump, the PoE restore) goes through
# session() and the process-wide _LOCK. A clean session is kept for
# SWITCH_SESSION_IDLE seconds and reused, then logged out. A session that
# ended in a timeout is aborted (Ctrl-C, drain), logged out with `exit`
# within SWITCH_LOGOUT_TIMEOUT, and only then is the transport closed hard
# as the fallback. After a timeout or a failed connect a circuit breaker
# refuses new connects for a cooldown that doubles per failure.

DEFAULT_SESSION_IDLE = 10.0
DEFAULT_LOGOUT_TIMEOUT = 3.0
DEFAULT_COOLDOWN_BASE = 30.0
DEFAULT_COOLDOWN_MAX = 600.0
ABORT_DRAIN_SECONDS = 2.0
CTRL_C = "\x03"
BREAKER_STATE = "ssh-breaker.json"


def _env_seconds(name: str, default: float, low: float, high: float) -> float:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        raise ValidationError(f"{name} must be a number of seconds, got {raw!r}.") from None
    if not low <= value <= high:
        raise ValidationError(f"{name} must be between {low:g} and {high:g} seconds.")
    return value


def session_idle() -> float:
    """SWITCH_SESSION_IDLE: keep a clean session this long for reuse (0 = log out after every call)."""
    return _env_seconds("SWITCH_SESSION_IDLE", DEFAULT_SESSION_IDLE, 0, 300)


def logout_timeout() -> float:
    """SWITCH_LOGOUT_TIMEOUT: how long `exit` may take before the transport is closed hard."""
    return _env_seconds("SWITCH_LOGOUT_TIMEOUT", DEFAULT_LOGOUT_TIMEOUT, 0.5, 30)


def cooldown_base() -> float:
    """SWITCH_COOLDOWN_BASE: first cooldown after a timeout or failed connect (0 = off)."""
    return _env_seconds("SWITCH_COOLDOWN_BASE", DEFAULT_COOLDOWN_BASE, 0, 3600)


def cooldown_max() -> float:
    """SWITCH_COOLDOWN_MAX: ceiling of the doubling cooldown."""
    return _env_seconds("SWITCH_COOLDOWN_MAX", DEFAULT_COOLDOWN_MAX, 1, 86400)


class _Breaker:
    """Circuit breaker for new SSH connections.

    State survives a server restart (SWITCH_STATE_DIR/ssh-breaker.json),
    so a hub restart or wake does not reopen the flood of connects.
    """

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.failures = 0
        self.until = 0.0  # time.time()
        self.reason = ""
        self.loaded = False

    def _load(self) -> None:
        if self.loaded:
            return
        self.loaded = True
        from lgs_switch_mcp import configstore  # no import cycle at module load

        data = configstore.read_state(BREAKER_STATE) or {}
        try:
            self.failures = int(data.get("failures", 0))
            self.until = float(data.get("until", 0.0))
            self.reason = str(data.get("reason", ""))
        except (TypeError, ValueError):
            self.failures, self.until, self.reason = 0, 0.0, ""

    def _save(self) -> None:
        from lgs_switch_mcp import configstore

        try:
            if self.failures:
                configstore.write_state(
                    BREAKER_STATE,
                    {"failures": self.failures, "until": self.until, "reason": self.reason},
                )
            else:
                configstore.clear_state(BREAKER_STATE)
        except OSError as exc:
            warn(f"SSH breaker state not stored ({exc}).", once_key="breaker-state")

    def check(self) -> None:
        if cooldown_base() <= 0:
            return
        with self.lock:
            self._load()
            left = self.until - time.time()
        if left > 0:
            raise SwitchConnectionError(
                f"Switch cooling down after {self.reason or 'an SSH failure'} "
                f"({self.failures} in a row); retry in {math.ceil(left)}s. No SSH "
                "connection was opened (SWITCH_COOLDOWN_BASE / SWITCH_COOLDOWN_MAX)."
            )

    def failure(self, reason: str) -> None:
        base = cooldown_base()
        with self.lock:
            self._load()
            self.failures += 1
            self.reason = reason
            if base > 0:
                cooldown = min(base * 2 ** (self.failures - 1), cooldown_max())
                self.until = time.time() + cooldown
            self._save()

    def success(self) -> None:
        with self.lock:
            self._load()
            if self.failures or self.until:
                self.failures, self.until, self.reason = 0, 0.0, ""
                self._save()

    def reset(self) -> None:
        with self.lock:
            self.failures, self.until, self.reason, self.loaded = 0, 0.0, "", False


_BREAKER = _Breaker()


@dataclass
class _Held:
    conn: Any
    session_log: bool
    last_used: float


# Guarded by _LOCK: the idle session kept for reuse, and the session in use.
_held: _Held | None = None
_active: Any = None
_idle_timer: threading.Timer | None = None
_timer_lock = threading.Lock()


def _acquire_lock() -> None:
    """Wait for the session lock, at most the call budget left (or one full
    budget for calls without a deadline). Never waits forever: a call that
    hung must not block every later call."""
    left = remaining_budget()
    wait = call_budget() if left is None else left
    if wait <= 0 or not _LOCK.acquire(timeout=wait):
        raise SwitchConnectionError(BUSY_MESSAGE.format(waited=max(0.0, round(wait, 1))))


_DIRTY_ATTR = "_lgs_switch_mcp_dirty"


def _mark_dirty(conn: Any) -> None:
    """Remember that this channel was left mid-command (timeout): it is
    aborted and logged out, never reused, even when the caller catches
    the error and finishes normally."""
    try:
        setattr(conn, _DIRTY_ATTR, True)
    except Exception:  # noqa: BLE001, S110 - best effort; never raised to the caller
        pass


def _is_dirty(conn: Any) -> bool:
    if getattr(conn, _DIRTY_ATTR, False) is True:
        return True
    left = remaining_budget()
    return left is not None and left <= 0


def _transport_alive(conn: Any) -> bool:
    """True while the SSH channel is open (no I/O: never writes a probe)."""
    channel = getattr(conn, "remote_conn", None)
    if channel is None:
        return False
    if getattr(channel, "closed", False) is True:
        return False
    transport = getattr(channel, "transport", None)
    is_active = getattr(transport, "is_active", None)
    return not (callable(is_active) and is_active() is False)


def _read_quietly(conn: Any) -> str:
    try:
        return conn.read_channel() or ""
    except Exception:  # noqa: BLE001 - a closed channel ends the drain
        raise EOFError from None


def _abort_command(conn: Any) -> str:
    """Interrupt whatever the switch is still printing: Ctrl-C, clear the
    line, quit a pager, then drain until a prompt or ABORT_DRAIN_SECONDS."""
    prompt_re = prompt_regex(conn)
    conn.write_channel(CTRL_C)
    conn.write_channel(CLEAR_LINE)
    conn.write_channel(getattr(conn, "RETURN", "\n"))
    end = time.monotonic() + ABORT_DRAIN_SECONDS
    tail = ""
    while time.monotonic() < end:
        try:
            chunk = _read_quietly(conn)
        except EOFError:
            break
        if not chunk:
            time.sleep(0.05)
            continue
        tail = (tail + chunk)[-2000:]
        last = visible_tail(tail)
        if PAGER_RE.search(last):
            conn.write_channel("q")
            continue
        if prompt_re.search(last):
            break
    return visible_tail(tail)


def _logout(conn: Any, last_line: str = "") -> bool:
    """Send `exit` (after `end` if still in config mode) and wait up to
    SWITCH_LOGOUT_TIMEOUT for the switch to close the channel."""
    ret = getattr(conn, "RETURN", "\n")
    if "(config" in last_line:
        conn.write_channel("end" + ret)
    conn.write_channel("exit" + ret)
    end = time.monotonic() + logout_timeout()
    while time.monotonic() < end:
        if not _transport_alive(conn):
            return True
        try:
            if not _read_quietly(conn):
                time.sleep(0.05)
        except EOFError:
            return True
    return not _transport_alive(conn)


def _hard_close(conn: Any) -> None:
    """Close the transport, then let netmiko release its session log and
    log filter (its graceful cleanup then fails fast on the closed channel)."""
    cleanup = getattr(conn, "paramiko_cleanup", None)
    if callable(cleanup):
        try:
            cleanup()
        except Exception:  # noqa: BLE001, S110 - best effort; never raised to the caller
            pass
    pre = getattr(conn, "remote_conn_pre", None)
    if pre is not None:
        try:
            pre.close()
        except Exception:  # noqa: BLE001, S110 - best effort; never raised to the caller
            pass
    try:
        conn.read_timeout_override = 1.0
    except Exception:  # noqa: BLE001, S110 - best effort; never raised to the caller
        pass
    try:
        conn.disconnect()
    except Exception:  # noqa: BLE001, S110 - best effort; never raised to the caller
        pass


def _close(conn: Any, *, abort: bool) -> None:
    """End a session completely; never leaves it open.

    abort=True (timeout, unknown channel state): Ctrl-C and drain first.
    Then `exit` with a short timeout; the hard transport close always
    follows as the fallback (a no-op when the switch already closed it).
    """
    last_line = ""
    try:
        if abort:
            last_line = _abort_command(conn)
        _logout(conn, last_line)
    except Exception:  # noqa: BLE001, S110 - the hard close below always runs
        pass
    finally:
        _hard_close(conn)


def _cancel_idle_timer() -> None:
    global _idle_timer
    with _timer_lock:
        if _idle_timer is not None:
            _idle_timer.cancel()
            _idle_timer = None


def _schedule_idle_close(seconds: float) -> None:
    global _idle_timer
    timer = threading.Timer(seconds, _close_if_idle)
    timer.daemon = True
    with _timer_lock:
        if _idle_timer is not None:
            _idle_timer.cancel()
        _idle_timer = timer
    timer.start()


def _close_if_idle() -> None:
    """Idle timer: log out the kept session unless a call is using it."""
    global _held
    if not _LOCK.acquire(blocking=False):
        return  # in use; it is parked (and the timer re-armed) on release
    try:
        held = _held
        if held is None:
            return
        try:
            idle = session_idle()
        except ValidationError:
            idle = 0.0
        if time.monotonic() - held.last_used + 0.05 < idle:
            _schedule_idle_close(idle - (time.monotonic() - held.last_used))
            return
        _held = None
        _close(held.conn, abort=False)
        redact_session_log_file()
    finally:
        _LOCK.release()


def _open(conn: Any) -> None:
    """Connect a ConnectHandler created with auto_connect=False.

    netmiko 4.8 leaks the authenticated transport when invoke_shell or the
    login handler fails inside the constructor (no reference comes back to
    close it). Opening it here keeps the reference, so _hard_close runs.
    """
    opener = getattr(conn, "_open", None)
    if callable(opener):
        opener()


def _connect(enable_session_log: bool, *, bypass_cooldown: bool = False) -> Any:
    """Open the one SSH session, unless the breaker is open."""
    params = connect_params(enable_session_log=enable_session_log)
    if not bypass_cooldown:
        _BREAKER.check()
    conn = None
    try:
        conn = ConnectHandler(**params, auto_connect=False)
        _open(conn)
        _check_budget("while connecting")
        disable_paging_best_effort(conn)
    except BaseException as exc:
        if conn is not None:
            _hard_close(conn)
        _BREAKER.failure("a failed or slow SSH connect")
        if isinstance(exc, (ValidationError, SwitchConnectionError)):
            raise
        if not isinstance(exc, Exception):
            raise
        raise wrap_transport_error(exc) from None
    return conn


def _take_or_connect(enable_session_log: bool, *, bypass_cooldown: bool = False) -> Any:
    """Reuse the kept session when it is alive and has the same session-log
    setting; otherwise log it out first, then connect (one session only)."""
    global _held
    held, _held = _held, None
    if held is not None:
        if held.session_log == enable_session_log and _transport_alive(held.conn):
            # The read timeout was cut to the budget of the call that
            # connected; give this call its own.
            held.conn.read_timeout_override = _netmiko_read_timeout()
            return held.conn
        _close(held.conn, abort=False)
    return _connect(enable_session_log, bypass_cooldown=bypass_cooldown)


def _release(conn: Any, *, clean: bool, enable_session_log: bool) -> None:
    """After a call: keep a clean session for reuse (or log it out when
    SWITCH_SESSION_IDLE is 0); abort and close anything else."""
    global _held
    if clean:
        _BREAKER.success()
        try:
            idle = session_idle()
        except ValidationError:
            idle = 0.0
        if idle > 0 and _transport_alive(conn):
            _held = _Held(conn, enable_session_log, time.monotonic())
            _schedule_idle_close(idle)
            return
        _close(conn, abort=False)
        return
    dirty = _is_dirty(conn)
    _close(conn, abort=dirty)
    if dirty:
        _BREAKER.failure("a command timeout")


def _check_budget(stage: str) -> None:
    left = remaining_budget()
    if left is not None and left <= 0:
        raise SwitchConnectionError(
            f"Call budget (SWITCH_CALL_BUDGET) used up {stage}; nothing more was sent."
        )


@contextmanager
def session(*, enable_session_log: bool = True, bypass_cooldown: bool = False) -> Iterator[Any]:
    """Yield the connected ConnectHandler, exclusive to one caller at a time.

    SNMP write tools pass enable_session_log=False so a community echo
    cannot sit in the session log in the clear. cisco_s300
    session_preparation already sends terminal width 511.

    The lock wait is bounded (see _acquire_lock). ``bypass_cooldown`` is
    only for the single PoE restore of poe_cycle (switching PoE back on
    must not wait for a cooldown).
    """
    global _active
    _acquire_lock()
    try:
        _cancel_idle_timer()
        conn = _take_or_connect(enable_session_log, bypass_cooldown=bypass_cooldown)
        _active = conn
        clean = False
        try:
            yield conn
            clean = not _is_dirty(conn)
        except ValidationError:
            raise
        except SwitchConnectionError:
            raise
        except Exception as exc:  # noqa: BLE001 - converted, redacted, re-raised
            _mark_dirty(conn)
            raise wrap_transport_error(exc) from None
        except BaseException:
            _mark_dirty(conn)  # interrupted mid-command: abort and close
            raise
        finally:
            _active = None
            _release(conn, clean=clean, enable_session_log=enable_session_log)
            redact_session_log_file()
    finally:
        _LOCK.release()


def shutdown(timeout: float = 5.0) -> None:
    """Graceful shutdown at process end: log out the kept session; a
    session still in use is closed hard. Safe to call more than once."""
    global _held
    _cancel_idle_timer()
    if _LOCK.acquire(timeout=timeout):
        try:
            held, _held = _held, None
            if held is not None:
                _close(held.conn, abort=False)
        finally:
            _LOCK.release()
        return
    active = _active
    if active is not None:
        _hard_close(active)


def reset_session_state() -> None:
    """Tests: drop the kept session and the breaker state in memory."""
    shutdown(timeout=1.0)
    _BREAKER.reset()


def send_paged(
    conn: Any,
    command: str,
    *,
    timeout: float | None = None,
    poll_interval: float = 0.1,
    confirm: tuple[re.Pattern[str], str] | None = None,
) -> str:
    """Send one exec command and read until the prompt, paging through pagers.

    Each time the last visible line matches PAGER_RE a single space is sent.
    Finishes when the last visible line is the device prompt. ``timeout`` is
    an idle timeout: the seconds allowed without any new output.

    ``confirm=(pattern, answer)`` answers one confirmation prompt (last
    visible line matches ``pattern``) with ``answer``. A second
    confirmation prompt is not answered and raises SwitchConnectionError.
    """
    limit = read_timeout() if timeout is None else timeout
    call_end = _DEADLINE.get()
    if call_end is not None and call_end - time.monotonic() <= 0:
        raise SwitchConnectionError(
            f"Call budget (SWITCH_CALL_BUDGET) used up before {command!r}; it was not sent."
        )
    prompt_re = prompt_regex(conn)
    # After 'save', "[OK]" can share the last line with the prompt.
    # Only then allow a prefix; a loose match on show output could cut a
    # running-config dump short if a line ended with the hostname and '#'.
    prompt_end = prompt_end_regex(conn, allow_prefix=confirm is not None)
    try:
        conn.clear_buffer()
    except Exception:  # noqa: BLE001, S110 - best effort; never raised to the caller
        pass
    conn.write_channel(command + getattr(conn, "RETURN", "\n"))
    buffer = ""
    scan_from = 0
    pages = 0
    confirms = 0
    started = time.monotonic()
    deadline = started + limit
    while True:
        if call_end is not None and time.monotonic() > call_end:
            _mark_dirty(conn)
            _raise_budget_exceeded(command, buffer, pages, time.monotonic() - started)
        chunk = conn.read_channel()
        if chunk:
            buffer += chunk
            deadline = time.monotonic() + limit
            tail = visible_tail(buffer[scan_from:])
            if PAGER_RE.search(tail):
                pages += 1
                if pages > MAX_PAGES:
                    _mark_dirty(conn)
                    raise SwitchConnectionError(f"Gave up after {MAX_PAGES} pager pages for {command!r}.")
                # Drop the pager line itself; PAGER_RE in clean_output is only
                # a fallback for prompts that are echoed elsewhere.
                cut = buffer.rfind("\n", scan_from)
                buffer = buffer[: cut + 1] if cut >= 0 else buffer[:scan_from]
                buffer += PAGE_BREAK
                conn.write_channel(" ")
                scan_from = len(buffer)
                continue
            if confirm is not None and confirm[0].search(tail):
                confirms += 1
                if confirms > 1:
                    _mark_dirty(conn)
                    raise SwitchConnectionError(
                        f"Unexpected second confirmation prompt after {command!r}; "
                        f"not answered (last line: {redact_secrets(tail[-80:])!r})."
                    )
                conn.write_channel(confirm[1] + getattr(conn, "RETURN", "\n"))
                scan_from = len(buffer)
                continue
            if "\n" in buffer and prompt_prefix(tail, prompt_end) is not None:
                return clean_output(buffer, command, prompt_re, prompt_end=prompt_end)
        elif time.monotonic() > deadline:
            _mark_dirty(conn)
            if _is_snmp_sensitive_show(command):
                # Fail closed: do not echo a possibly secret last line
                # (foreign community, or unknown user-key layout).
                raise SwitchConnectionError(
                    f"No prompt after {command!r} ({limit:g}s without new output, "
                    f"pages: {pages})."
                )
            last = visible_tail(buffer)[-80:]
            raise SwitchConnectionError(
                f"No prompt after {command!r} ({limit:g}s without new output, "
                f"pages: {pages}, last line: {redact_show_output(command, last)!r})."
            )
        else:
            time.sleep(poll_interval)


def _raise_budget_exceeded(command: str, buffer: str, pages: int, elapsed: float) -> None:
    """The call budget ran out while ``command`` was still producing output
    (or before its prompt came back). The caller aborts and closes the session."""
    detail = f"after {elapsed:.0f}s, pages: {pages}"
    if not _is_snmp_sensitive_show(command):
        last = visible_tail(buffer)[-80:]
        detail += f", last line: {redact_show_output(command, last)!r}"
    raise SwitchConnectionError(
        f"Gave up on {command!r}: call budget (SWITCH_CALL_BUDGET) used up "
        f"({detail}). The session was closed; later calls start fresh."
    )


SEQUENCE_SKIPPED = "not run: an earlier command in the same session failed"


def run_show_sequence(commands: list[str]) -> list[tuple[str, str | None, str | None]]:
    """Run several exec commands in one session, in order.

    Returns ``(command, output, error)`` per command; exactly one of output
    and error is set. After the first failing command the remaining ones are
    not sent (the channel state is unknown) and get ``SEQUENCE_SKIPPED``.
    Connect failures raise ``SwitchConnectionError`` / ``ValidationError`` as
    ``run_show`` does. Callers must pass only filtered show commands.
    """
    results: list[tuple[str, str | None, str | None]] = []
    # As run_shows: keep community / viewtree / user listings out of the
    # netmiko session log.
    enable_session_log = not any(_is_snmp_sensitive_show(command) for command in commands)
    with session(enable_session_log=enable_session_log) as conn:
        failed = False
        for command in commands:
            if failed:
                results.append((command, None, SEQUENCE_SKIPPED))
                continue
            try:
                results.append((command, _send_show(conn, command), None))
            except SwitchConnectionError as exc:
                failed = True
                results.append((command, None, redact_secrets(str(exc))))
    return results


def _send_show(conn: Any, command: str) -> str:
    """send_paged_redacted (pager, secret and community redaction) with every
    failure turned into a redacted SwitchConnectionError."""
    try:
        return send_paged_redacted(conn, command)
    except SwitchConnectionError:
        raise
    except Exception as exc:  # noqa: BLE001 - converted, redacted, re-raised (as run_show)
        raise wrap_transport_error(exc) from None


def send_paged_redacted(conn: Any, command: str) -> str:
    """send_paged, then redact secrets (and community listings)."""
    return redact_show_output(command, send_paged(conn, command))


def run_show(command: str) -> str:
    # Community / viewtree / user listings can contain secrets; do not
    # leave them in the netmiko session log until disconnect.
    enable_session_log = not _is_snmp_sensitive_show(command)
    with session(enable_session_log=enable_session_log) as conn:
        return send_paged_redacted(conn, command)


def run_shows(commands: list[str]) -> dict[str, str]:
    """Run several exec commands in one session; values are already redacted."""
    enable_session_log = not any(_is_snmp_sensitive_show(command) for command in commands)
    with session(enable_session_log=enable_session_log) as conn:
        return {command: send_paged_redacted(conn, command) for command in commands}


# A CLI error line on ISS starts with "%" ("% Invalid input", "% Error").
CONFIG_ERROR_PATTERN = r"%"


def _send_config(
    conn: Any, commands: list[str], *, error_pattern: str | None = None
) -> str:
    """Send a config set. With ``error_pattern``, netmiko stops at the first
    command whose output matches it, so later commands are never sent."""
    kwargs: dict[str, Any] = {}
    if error_pattern is not None:
        kwargs["error_pattern"] = error_pattern
    _bump_config_generation()
    try:
        output = conn.send_config_set(
            commands,
            exit_config_mode=True,
            cmd_verify=True,
            read_timeout=read_timeout(),
            **kwargs,
        )
    except Exception as exc:  # noqa: BLE001 - best effort; never raised to the caller
        if _commands_include_snmp_community(commands):
            # Never return or log str(exc): netmiko cmd_verify timeouts
            # embed repr(re.escape(command)), which bypasses exact redaction.
            raise SwitchConnectionError(
                "Device rejected the configuration sequence "
                f"({type(exc).__name__}). The exception text is omitted "
                "because the sequence may include a community string."
            ) from None
        raise wrap_transport_error(exc) from None
    text = output if isinstance(output, str) else str(output)
    if config_output_is_error(text, commands=commands):
        if _commands_include_snmp_community(commands):
            # Never return or audit device text: wrap, ANSI erase, or a
            # mid-line prompt redraw can split a community token so span
            # and exact redaction miss fragments.
            raise SwitchConnectionError(
                "Device rejected the configuration sequence. "
                "The device output is omitted because the sequence may "
                "include a community string."
            )
        raise SwitchConnectionError(
            "Device rejected the configuration sequence:\n" + redact_device_text(text)
        )
    return redact_device_text(text)


def run_config_set(commands: list[str]) -> str:
    with session() as conn:
        return _send_config(conn, commands)


def run_config_and_readback(commands: list[str], readback: str) -> str:
    """Apply a config set, then read the resulting state in the same session."""
    with session() as conn:
        _send_config(conn, commands)
        try:
            state_text = send_paged(conn, readback)
        except Exception as exc:  # noqa: BLE001 - best effort; never raised to the caller
            raise wrap_transport_error(
                exc,
                message=(
                    "Configuration was sent, but read-back failed: "
                    + redact_secrets(str(exc))
                ),
            ) from None
        return (
            "Configuration sent.\n"
            f"--- {readback} ---\n"
            f"{redact_show_output(readback, state_text)}"
        )


def run_config_and_readbacks(
    commands: list[str],
    readbacks: list[str],
    *,
    enable_session_log: bool = True,
) -> str:
    """Apply a config set, then run one or more exec read-backs in the same session."""
    with session(enable_session_log=enable_session_log) as conn:
        _send_config(conn, commands)
        sections: list[str] = ["Configuration sent."]
        for readback in readbacks:
            try:
                state_text = send_paged_redacted(conn, readback)
            except SwitchConnectionError as exc:
                raise SwitchConnectionError(
                    "Configuration was sent, but read-back failed: "
                    + redact_secrets(str(exc))
                ) from None
            sections.append(f"--- {readback} ---\n{state_text}")
        return "\n".join(sections)


def run_in_session(
    callback: Any,
    *,
    enable_session_log: bool = True,
    bypass_cooldown: bool = False,
) -> Any:
    """Run ``callback(conn)`` inside a locked session. Output must be redacted by the caller if needed."""
    with session(enable_session_log=enable_session_log, bypass_cooldown=bypass_cooldown) as conn:
        return callback(conn)


def save_in_session(conn: Any) -> str:
    """Send 'save' on an open session; answer one Y/N confirmation with 'y'
    (prompt not live-confirmed)."""
    _bump_config_generation()
    try:
        text = send_paged(conn, "save", confirm=(SAVE_CONFIRM_RE, SAVE_CONFIRM_ANSWER))
    except Exception as exc:  # noqa: BLE001 - best effort; never raised to the caller
        # SwitchConnectionError messages are already redacted; redact again
        # for anything else (idempotent).
        raise wrap_transport_error(
            exc,
            message=(
                f"save did not complete: {redact_secrets(str(exc))} Whether "
                "startup-config was written is unknown; check it before "
                "saving again."
            ),
        ) from None
    if config_output_is_error(text, commands=["save"]):
        raise SwitchConnectionError("save failed:\n" + redact_device_text(text))
    return redact_device_text(text)


def run_save() -> str:
    """Send 'save' in its own session (see save_in_session)."""
    with session() as conn:
        return save_in_session(conn)


# Ctrl-U clears the typed line on ISS/Cisco-style CLIs.
CLEAR_LINE = "\x15"
HELP_IDLE_SECONDS = 2.0


def send_help(conn: Any, text: str, *, idle: float = HELP_IDLE_SECONDS) -> str:
    """Type ``text`` followed by ``?`` (no Enter), read the help listing,
    then clear the line with Ctrl-U and return to a clean prompt.

    Nothing is executed: the line is never submitted. The listing is read
    until ``idle`` seconds pass without new output (help prompts redraw
    the typed line, so the normal prompt check does not apply). Pager
    prompts are answered with a space. The caller must redact the result.
    """
    prompt_re = prompt_regex(conn)
    try:
        conn.clear_buffer()
    except Exception:  # noqa: BLE001, S110 - best effort; never raised to the caller
        pass
    conn.write_channel(f"{text} ?")
    buffer = ""
    pages = 0
    hard_deadline = time.monotonic() + read_timeout()
    call_end = _DEADLINE.get()
    if call_end is not None:
        hard_deadline = min(hard_deadline, call_end)
    last_output = time.monotonic()
    while True:
        chunk = conn.read_channel()
        now = time.monotonic()
        if chunk:
            buffer += chunk
            last_output = now
            if PAGER_RE.search(visible_tail(buffer)):
                pages += 1
                if pages > MAX_PAGES:
                    break
                conn.write_channel(" ")
            continue
        if now - last_output >= idle or now > hard_deadline:
            break
        time.sleep(0.1)
    # Clear the redrawn partial line, then get a fresh prompt.
    conn.write_channel(CLEAR_LINE)
    conn.write_channel(getattr(conn, "RETURN", "\n"))
    settle = time.monotonic() + read_timeout()
    if call_end is not None:
        settle = min(settle, max(call_end, time.monotonic() + 1.0))
    tail = ""
    while time.monotonic() < settle:
        chunk = conn.read_channel()
        if chunk:
            tail += chunk
            if prompt_re.search(visible_tail(tail)):
                break
        else:
            time.sleep(0.1)
    text_out = clean_output(buffer, f"{text} ?", prompt_re)
    lines = [
        line
        for line in text_out.splitlines()
        if not (prompt_re.search(line) or line.strip().endswith(text.strip()))
    ]
    return "\n".join(lines).strip("\n")


__all__ = [
    "BUSY_MESSAGE",
    "CONFIG_ERROR_PATTERN",
    "DEFAULT_CALL_BUDGET",
    "DEFAULT_READ_TIMEOUT",
    "MAX_PAGES",
    "MAX_READ_TIMEOUT",
    "PAGER_RE",
    "PAGE_BREAK",
    "PAGING_OFF_CONFIG",
    "READBACK_DESCRIPTION",
    "READBACK_INTERFACE",
    "READBACK_POE",
    "SAVE_CONFIRM_ANSWER",
    "SAVE_CONFIRM_RE",
    "SEQUENCE_SKIPPED",
    "ConnectionError",
    "SwitchConnectionError",
    "build_admin_state_commands",
    "build_description_commands",
    "build_poe_commands",
    "call_budget",
    "call_deadline",
    "clean_output",
    "config_generation",
    "connect_params",
    "disable_paging_best_effort",
    "logout_timeout",
    "paging_off_enabled",
    "prepare_private_file",
    "read_timeout",
    "redact_session_log_file",
    "redact_show_output",
    "remaining_budget",
    "reset_session_state",
    "run_config_and_readback",
    "run_config_and_readbacks",
    "run_config_set",
    "run_in_session",
    "run_save",
    "run_show",
    "run_show_sequence",
    "run_shows",
    "save_in_session",
    "send_help",
    "send_paged",
    "send_paged_redacted",
    "session",
    "session_idle",
    "session_log_path",
    "shutdown",
    "warn",
    "wrap_transport_error",
]
