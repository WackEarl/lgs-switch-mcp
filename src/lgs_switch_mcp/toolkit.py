"""Shared helpers for MCP tool functions: audit wrappers, allowlist filter, JSON."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from netmiko_mcp.security import (
    build_abbreviation_filter,
    load_commands,
    validate_command,
)

from lgs_switch_mcp.audit import write_audit
from lgs_switch_mcp.validation import redact_secrets


def with_audit_warning(text: str, warning: str | None) -> str:
    if not warning:
        return text
    return f"{text}\n\naudit_warning: {warning}"


def fail(tool: str, params: dict[str, Any], message: str, *, allowed: bool) -> str:
    text = redact_secrets(message)
    warning = write_audit(tool=tool, params=params, allowed=allowed, result=text)
    return with_audit_warning(text, warning)


def ok(tool: str, params: dict[str, Any], result: str, *, audit_result: str = "ok") -> str:
    """Audit a successful call. The result gets the exact-secret redaction
    again (defense in depth; device text is already redacted)."""
    warning = write_audit(tool=tool, params=params, allowed=True, result=audit_result)
    return with_audit_warning(redact_secrets(result), warning)


def prepare_runtime() -> None:
    """Point netmiko-mcp's command-file singleton at NETMIKO_MCP_COMMAND_FILE."""
    command_file = (os.environ.get("NETMIKO_MCP_COMMAND_FILE") or "").strip()
    if not command_file:
        return
    from netmiko_mcp.config import settings

    settings.command_file = str(Path(command_file).expanduser())
    load_commands.cache_clear()
    build_abbreviation_filter.cache_clear()


COMMAND_FILE_MISSING = "Error: NETMIKO_MCP_COMMAND_FILE is not set or the file does not exist."


def command_file_ready() -> bool:
    command_file = (os.environ.get("NETMIKO_MCP_COMMAND_FILE") or "").strip()
    return bool(command_file) and Path(command_file).expanduser().is_file()


def filter_commands(commands: list[str] | tuple[str, ...]) -> tuple[list[tuple[str, str]], list[str]]:
    """Run hardcoded show commands through the netmiko-mcp allowlist.

    Returns ``([(command, normalized)], errors)``. Read tools use this so an
    operator can still narrow them by editing commands.yml.
    """
    prepare_runtime()
    allowed: list[tuple[str, str]] = []
    errors: list[str] = []
    for command in commands:
        verdict = validate_command(command)
        if verdict.allowed:
            allowed.append((command, verdict.normalized_command))
        else:
            errors.append(f"{command}: Command rejected: {verdict.reason}")
    return allowed, errors


def to_json(data: Any) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False, sort_keys=False)


__all__ = [
    "COMMAND_FILE_MISSING",
    "command_file_ready",
    "fail",
    "filter_commands",
    "ok",
    "prepare_runtime",
    "to_json",
    "with_audit_warning",
]
