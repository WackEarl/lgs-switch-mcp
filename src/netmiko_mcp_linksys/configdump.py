"""Running-config dump that may take longer than one tool call.

``show current running-config`` is the slowest read on the LGS (many pager
pages over a slow CLI). Retest 0.3.1: ``config_read("running")`` ended
twice with MCP error -32001, the caller's request timeout, while the dump
was still running; the worker thread kept the session lock after that.

Here the dump runs in a background job with its own limit
(SWITCH_CONFIG_DUMP_TIMEOUT). A tool call waits for it only as long as its
call budget allows. If the dump is not finished by then, the call answers
``Pending``, and the next config call picks up the finished result once
(within PICKUP_SECONDS, and never after a configuration change through
this server, see ``config_generation``). Every other call starts a fresh
dump, so a backup is never an old copy.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from netmiko_mcp_linksys.connection import (
    call_budget,
    call_deadline,
    config_generation,
    remaining_budget,
    run_in_session,
    send_paged_redacted,
    warn,
)
from netmiko_mcp_linksys.errors import SwitchConnectionError
from netmiko_mcp_linksys.validation import ValidationError, redact_secrets
from netmiko_mcp_linksys.writes import read_config

# Same command as readtools.SHOW_SYSTEM (readtools imports this module).
SHOW_SYSTEM = "show system information"

DEFAULT_DUMP_TIMEOUT = 240.0
# How long a finished dump that nobody picked up yet is handed out.
PICKUP_SECONDS = 300.0
# Seconds kept free at the end of a call budget to build the answer.
ANSWER_MARGIN = 2.0


class ConfigDumpPending(Exception):
    """The dump is still running; the message says when to call again."""


def _seconds_env(name: str, default: float, low: float, high: float) -> float:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        raise ValidationError(f"{name} must be a number of seconds, got {raw!r}.") from None
    if not low <= value <= high:
        raise ValidationError(f"{name} must be between {int(low)} and {int(high)} seconds.")
    return value


def dump_timeout() -> float:
    return _seconds_env("SWITCH_CONFIG_DUMP_TIMEOUT", DEFAULT_DUMP_TIMEOUT, 30, 600)


@dataclass
class Dump:
    """A finished, masked running-config read."""

    config: str
    read_at: str  # UTC ISO time when the dump finished
    finished: float  # time.monotonic()
    duration_s: float
    generation: int
    system: str | None = None

    def age(self) -> float:
        return time.monotonic() - self.finished

    def info(self) -> dict[str, Any]:
        return {
            "read_at": self.read_at,
            "dump_seconds": round(self.duration_s, 1),
            "age_seconds": round(self.age(), 1),
        }


@dataclass
class _Job:
    generation: int
    started: float = field(default_factory=time.monotonic)
    done: threading.Event = field(default_factory=threading.Event)
    result: Dump | None = None
    error: BaseException | None = None


_state_lock = threading.Lock()
_job: _Job | None = None


def _read(conn: Any) -> tuple[str, str]:
    config = read_config(conn, "running")
    try:
        system = send_paged_redacted(conn, SHOW_SYSTEM)
    except SwitchConnectionError:
        system = ""
    return config, system


def _run_job(job: _Job, limit: float) -> None:
    try:
        with call_deadline(limit):
            config, system = run_in_session(_read, enable_session_log=False)
        dump = Dump(
            config=config,
            read_at=datetime.now(UTC).isoformat(timespec="seconds"),
            finished=time.monotonic(),
            duration_s=time.monotonic() - job.started,
            generation=job.generation,
            system=system,
        )
        job.result = dump
    except BaseException as exc:  # noqa: BLE001 - handed to the waiting call
        job.error = exc
        warn(f"running-config dump failed: {redact_secrets(str(exc))}")
    finally:
        job.done.set()


def running_config() -> Dump:
    """Return a masked running-config dump within the current call budget.

    Raises ConfigDumpPending when the background dump is not finished in
    time, or the dump's own SwitchConnectionError / ValidationError /
    ConfigUnavailableError.
    """
    global _job
    limit = dump_timeout()
    with _state_lock:
        job = _job
        if job is None or (job.done.is_set() and not _deliverable(job)):
            job = _Job(generation=config_generation())
            _job = job
            threading.Thread(
                target=_run_job, args=(job, limit), name="running-config-dump", daemon=True
            ).start()
    left = remaining_budget()
    wait = (call_budget() if left is None else left) - ANSWER_MARGIN
    if not job.done.wait(timeout=max(0.0, wait)):
        elapsed = time.monotonic() - job.started
        raise ConfigDumpPending(
            f"running-config dump still in progress ({elapsed:.0f}s so far, limit "
            f"{limit:.0f}s, SWITCH_CONFIG_DUMP_TIMEOUT). Nothing failed; call again in "
            "about 30 s to get the result."
        )
    with _state_lock:
        if _job is job:
            _job = None  # delivered once; the next call starts a fresh dump
    if job.error is not None:
        raise job.error
    assert job.result is not None
    return job.result


def _deliverable(job: _Job) -> bool:
    """A finished job whose result nobody has picked up yet, still valid."""
    if job.error is not None:
        return False
    return (
        job.result is not None
        and job.result.generation == config_generation()
        and job.result.age() <= PICKUP_SECONDS
    )


def reset() -> None:
    """Forget a pending or finished job (tests)."""
    global _job
    with _state_lock:
        _job = None


__all__ = [
    "ConfigDumpPending",
    "Dump",
    "dump_timeout",
    "reset",
    "running_config",
]
