"""Write pipeline shared by the configuration tools.

Every write tool builds a ``WritePlan`` and hands it to ``execute``:

* ``dry_run=True`` (the tool default): one session reads the current state
  (the plan's read-back commands), nothing is sent. The result lists the
  exact CLI lines, the current state and the expected state.
* ``dry_run=False``: in one session the current state is read, a masked
  running-config snapshot is stored (``SWITCH_PRE_WRITE_SNAPSHOT``), the
  stages are sent with ``%`` as error pattern (netmiko stops at the first
  failing line), the state is read back and a before/after diff is
  returned.

Nothing here saves to startup-config.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from lgs_switch_mcp import configstore
from lgs_switch_mcp.commands import CONFIG_SHOW, STARTUP_UNAVAILABLE
from lgs_switch_mcp.connection import (
    CONFIG_ERROR_PATTERN,
    SwitchConnectionError,
    _send_config,
    run_in_session,
    send_paged,
    send_paged_redacted,
)
from lgs_switch_mcp.errors import wrap_transport_error
from lgs_switch_mcp.redaction import redact_device_text
from lgs_switch_mcp.tables import interface_config_block
from lgs_switch_mcp.validation import (
    ValidationError,
    config_output_is_error,
    redact_secrets,
)

SNAPSHOT_MODES = ("required", "best-effort", "off")
NOT_SAVED = "Not saved to startup-config. Use save_config to persist."


def snapshot_mode() -> str:
    """SWITCH_PRE_WRITE_SNAPSHOT: required (default) | best-effort | off."""
    raw = (os.environ.get("SWITCH_PRE_WRITE_SNAPSHOT") or "required").strip().lower()
    if raw not in SNAPSHOT_MODES:
        raise ValidationError(
            "SWITCH_PRE_WRITE_SNAPSHOT must be one of: " + ", ".join(SNAPSHOT_MODES) + "."
        )
    return raw


@dataclass
class Stage:
    """Commands sent together. ``exec_mode`` stages go to privileged exec
    one by one; config stages go through send_config_set. ``guard`` runs
    right before the stage on the open session and may raise
    ValidationError to stop (earlier stages stay applied and are reported)."""

    commands: list[str]
    exec_mode: bool = False
    guard: Callable[[Any], None] | None = None


@dataclass
class WritePlan:
    tool: str
    stages: list[Stage]
    readbacks: list[str] = field(default_factory=list)
    expected: str = ""
    warnings: list[str] = field(default_factory=list)
    # Port whose interface block from running-config is shown as before/after.
    config_block_port: str | None = None
    # Take the pre-write snapshot (config changes). Off for exec-only tools.
    snapshot: bool = True
    after_write: Callable[[], None] | None = None
    # Re-detect the CLI prompt after sending (set switch-name changes it).
    refresh_prompt: bool = False

    @property
    def commands(self) -> list[str]:
        return [command for stage in self.stages for command in stage.commands]


class ConfigUnavailableError(SwitchConnectionError):
    """The device has no CLI command for this config source (startup)."""


def read_config(conn: Any, source: str = "running") -> str:
    """Read the running-config on an open session, masked.

    ``startup`` raises ConfigUnavailableError without sending anything (the
    LGS CLI has no show command for it). Raises SwitchConnectionError when
    the device rejects ``show current running-config``."""
    source = configstore.validate_source(source)
    if source not in CONFIG_SHOW:
        raise ConfigUnavailableError(STARTUP_UNAVAILABLE)
    command = CONFIG_SHOW[source]
    try:
        raw = send_paged(conn, command)
    except SwitchConnectionError:
        raise
    except Exception as exc:  # noqa: BLE001 - converted and redacted
        raise wrap_transport_error(exc) from None
    masked = redact_device_text(raw)
    if not masked.strip() or _looks_rejected(masked):
        first = masked.strip().splitlines()[0] if masked.strip() else "(empty output)"
        raise SwitchConnectionError(f"{command} is not available on this device: {first}")
    return masked


# Only the first lines are checked: a config dump may contain "error"
# (descriptions, errdisable), but a rejected command answers at once.
_REJECTED_RE = re.compile(
    r"^\s*%|invalid input|unrecognized command|incomplete command|unknown command",
    re.IGNORECASE,
)


def _looks_rejected(text: str) -> bool:
    head = [line for line in text.splitlines() if line.strip()][:3]
    return any(_REJECTED_RE.search(line) for line in head)


def _read_states(conn: Any, readbacks: list[str]) -> dict[str, str]:
    states: dict[str, str] = {}
    for command in readbacks:
        try:
            states[command] = send_paged_redacted(conn, command)
        except SwitchConnectionError as exc:
            states[command] = f"[read failed: {redact_secrets(str(exc))}]"
        except Exception as exc:  # noqa: BLE001
            states[command] = f"[read failed: {redact_secrets(str(wrap_transport_error(exc)))}]"
    return states


def _block(config: str | None, port: str) -> str | None:
    if config is None:
        return None
    return "\n".join(interface_config_block(config, port))


def _send_exec(conn: Any, command: str) -> str:
    try:
        text = send_paged(conn, command)
    except SwitchConnectionError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise wrap_transport_error(exc) from None
    masked = redact_device_text(text)
    if config_output_is_error(masked, commands=[command]):
        raise SwitchConnectionError(f"Device rejected {command!r}:\n{masked}")
    return masked


def take_snapshot(conn: Any, tool: str) -> dict[str, Any]:
    """Store a masked running-config snapshot per SWITCH_PRE_WRITE_SNAPSHOT.

    ``required``: failure raises (the write is refused before anything is
    sent). ``best-effort``: failure is reported. ``off``: skipped."""
    mode = snapshot_mode()
    if mode == "off":
        return {"skipped": "SWITCH_PRE_WRITE_SNAPSHOT=off"}
    try:
        masked = read_config(conn, "running")
        stored = configstore.store_backup(masked, "running", tag=f"pre-{tool}")
    except (SwitchConnectionError, OSError, ValidationError) as exc:
        message = redact_secrets(str(exc))
        if mode == "required":
            raise SwitchConnectionError(
                "Pre-write snapshot failed, nothing was sent: "
                f"{message} (set SWITCH_PRE_WRITE_SNAPSHOT=best-effort to "
                "write without a snapshot)."
            ) from None
        return {"failed": message}
    stored.pop("diff", None)
    stored["config"] = masked
    return stored


def execute(plan: WritePlan, *, dry_run: bool) -> str:
    """Run the plan (see module docstring). Returns a JSON document.

    Raises ValidationError / SwitchConnectionError; messages are redacted.
    """

    def _run(conn: Any) -> dict[str, Any]:
        before = _read_states(conn, plan.readbacks)
        config_before: str | None = None
        warnings = list(plan.warnings)
        result: dict[str, Any] = {"tool": plan.tool, "dry_run": dry_run}
        if dry_run:
            if plan.config_block_port is not None:
                try:
                    config_before = read_config(conn, "running")
                except SwitchConnectionError as exc:
                    warnings.append(f"Current interface config unavailable: {exc}")
            result.update(
                sent=False,
                commands=plan.commands,
                current=before,
                expected=plan.expected,
            )
            if plan.config_block_port is not None:
                result["current_interface_config"] = _block(config_before, plan.config_block_port)
            result["warnings"] = warnings
            result["note"] = "Dry run: nothing was sent. Call again with dry_run=false to apply."
            return result

        snapshot: dict[str, Any] = {"skipped": "not a configuration change"}
        if plan.snapshot:
            snapshot = take_snapshot(conn, plan.tool)
            config_before = snapshot.pop("config", None)
        if plan.config_block_port is not None and config_before is None:
            try:
                config_before = read_config(conn, "running")
            except SwitchConnectionError as exc:
                warnings.append(f"Interface config before the change unavailable: {exc}")

        sent: list[str] = []
        outputs: list[str] = []
        try:
            for stage in plan.stages:
                if stage.guard is not None:
                    stage.guard(conn)
                if stage.exec_mode:
                    for command in stage.commands:
                        outputs.append(_send_exec(conn, command))
                        sent.append(command)
                else:
                    outputs.append(
                        _send_config(conn, stage.commands, error_pattern=CONFIG_ERROR_PATTERN)
                    )
                    sent.extend(stage.commands)
        except (ValidationError, SwitchConnectionError) as exc:
            if not sent:
                raise
            # Partial: report what was applied.
            raise SwitchConnectionError(
                f"Stopped after sending {sent!r}: {redact_secrets(str(exc))} "
                "The commands above are applied (not saved). Check the state "
                "before retrying."
            ) from None

        if plan.refresh_prompt:
            try:
                conn.set_base_prompt()
            except Exception as exc:  # noqa: BLE001 - reported, read-back may fail
                warnings.append(f"Prompt re-detection failed: {redact_secrets(str(exc))}")
        after = _read_states(conn, plan.readbacks)
        result.update(sent=True, commands=sent, snapshot=snapshot)
        result["device_output"] = "\n".join(o for o in outputs if o.strip())
        result["before"] = before
        result["after"] = after
        result["diff"] = {
            command: configstore.unified_diff(
                before.get(command, ""), after.get(command, ""),
                before_label="before", after_label="after",
            )
            for command in plan.readbacks
        }
        if plan.config_block_port is not None:
            try:
                config_after: str | None = read_config(conn, "running")
            except SwitchConnectionError as exc:
                config_after = None
                warnings.append(f"Interface config after the change unavailable: {exc}")
            block_before = _block(config_before, plan.config_block_port)
            block_after = _block(config_after, plan.config_block_port)
            result["interface_config_before"] = block_before
            result["interface_config_after"] = block_after
            if block_before is not None and block_after is not None:
                result["diff"]["interface config"] = configstore.unified_diff(
                    block_before, block_after, before_label="before", after_label="after"
                )
        result["expected"] = plan.expected
        result["warnings"] = warnings
        result["note"] = NOT_SAVED
        return result

    data = run_in_session(_run, enable_session_log=False)
    if not dry_run and plan.after_write is not None:
        plan.after_write()
    return json.dumps(data, indent=2, ensure_ascii=False)


__all__ = [
    "NOT_SAVED",
    "SNAPSHOT_MODES",
    "ConfigUnavailableError",
    "Stage",
    "WritePlan",
    "execute",
    "read_config",
    "snapshot_mode",
    "take_snapshot",
]
