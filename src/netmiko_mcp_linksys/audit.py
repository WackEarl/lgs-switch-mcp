"""JSON-lines audit log. Never records passwords. Never breaks a tool call."""

from __future__ import annotations

import functools
import json
import os
import time
import uuid
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from netmiko_mcp_linksys.connection import prepare_private_file, warn
from netmiko_mcp_linksys.validation import redact_secrets


def _redact_obj(value: Any) -> Any:
    if isinstance(value, str):
        return redact_secrets(value)
    if isinstance(value, dict):
        return {str(key): _redact_obj(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_obj(item) for item in value]
    return value


@dataclass
class _Call:
    call_id: str
    started: float
    finished: bool = False


_CURRENT_CALL: ContextVar[_Call | None] = ContextVar("audit_call", default=None)


def audit_path() -> str:
    return (os.environ.get("SWITCH_AUDIT_LOG") or "").strip()


def write_audit(
    *,
    tool: str,
    params: dict[str, Any],
    allowed: bool,
    result: str,
) -> str | None:
    """Append one audit line. Return a warning string on failure, else None.

    Failures (read-only file system, permissions, full disk, ...) are written
    to stderr and returned so the caller can surface them; they never raise.
    """
    path_str = audit_path()
    if not path_str:
        return None

    record: dict[str, Any] = {
        "time": datetime.now(UTC).isoformat(),
        "tool": tool,
        "params": params,
        "allowed": allowed,
        "result": result,
    }
    call = _CURRENT_CALL.get()
    if call is not None and not call.finished:
        call.finished = True
        record["call_id"] = call.call_id
        record["duration_ms"] = int((time.monotonic() - call.started) * 1000)
    return _append(path_str, record)


def _append(path_str: str, record: dict[str, Any]) -> str | None:
    try:
        record = dict(record)
        if "params" in record:
            record["params"] = _redact_obj(record["params"])
        if isinstance(record.get("result"), str):
            record["result"] = redact_secrets(record["result"])
        line = redact_secrets(json.dumps(record, ensure_ascii=True, separators=(",", ":")))
        path = prepare_private_file(path_str)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except Exception as exc:  # noqa: BLE001 - the audit log never breaks a tool call
        message = redact_secrets(f"audit log {path_str} not written: {exc}")
        warn(message)
        return message
    return None


def audited_call[F: Callable[..., Any]](function: F) -> F:
    """Wrap an MCP tool so every call is visible in the audit log, even one
    that never returns a result to the client.

    A ``"phase": "start"`` record (with a call id) is written before the
    tool runs; the tool's normal audit record carries the same call id and
    ``duration_ms``. If the tool raises instead of returning, an error
    record is written for it. A start record without a matching result
    therefore marks a call that was cut off (hub timeout such as MCP error
    -32001, server restart) or is still running; audit_tail reports it.
    """

    @functools.wraps(function)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        tool = function.__name__
        call = _Call(call_id=uuid.uuid4().hex[:12], started=time.monotonic())
        token = _CURRENT_CALL.set(call)
        path_str = audit_path()
        try:
            if path_str:
                _append(path_str, {
                    "time": datetime.now(UTC).isoformat(),
                    "tool": tool,
                    "phase": "start",
                    "call_id": call.call_id,
                })  # no params here: the tool decides what it may log
            try:
                result = function(*args, **kwargs)
            except BaseException as exc:
                if not call.finished:
                    write_audit(
                        tool=tool, params={}, allowed=True,
                        result=f"Error: call ended without a result ({type(exc).__name__})",
                    )
                raise
            if not call.finished:
                write_audit(tool=tool, params={}, allowed=True, result="returned")
            return result
        finally:
            _CURRENT_CALL.reset(token)

    return wrapper  # type: ignore[return-value]


def check_audit_path() -> str | None:
    """Startup check: verify SWITCH_AUDIT_LOG is writable. Warn, never abort."""
    path_str = audit_path()
    if not path_str:
        warn("SWITCH_AUDIT_LOG is not set; tool calls are not audited.")
        return None
    try:
        path = prepare_private_file(path_str)
        if not os.access(path, os.W_OK):
            raise PermissionError(f"{path} is not writable")
    except Exception as exc:  # noqa: BLE001 - the audit log never breaks a tool call
        message = redact_secrets(
            f"SWITCH_AUDIT_LOG {path_str} is not writable ({exc}). Tools keep "
            "working, but audit entries will be missing and results will carry "
            "an audit_warning line."
        )
        warn(message)
        return message
    return None


__all__ = ["audited_call", "check_audit_path", "write_audit"]
