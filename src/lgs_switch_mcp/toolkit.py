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


def _normalized_show_command(command: str) -> str:
    return " ".join(command.split()).lower()


def _is_show_version_form(command: str) -> bool:
    """Cisco-style 'show version' and short forms denied as that command.

    Live checks on this firmware found 'show version' is not a valid LGS
    command. 'vlan' and similar nouns are not treated as 'version'.
    """
    words = _normalized_show_command(command).split()
    if len(words) != 2:
        return False
    verb, noun = words
    if not "show".startswith(verb) or len(verb) < 2:
        return False
    return "version".startswith(noun) and len(noun) >= 3


def _is_config_dump_show(command: str) -> bool:
    text = _normalized_show_command(command)
    return text.startswith(
        ("show current", "show running-config", "show startup-config")
    )


def _allowed_prefix_completions(command: str) -> list[str]:
    """Allowed exact commands that continue the submitted prefix with more words."""
    normalized = _normalized_show_command(command)
    if not normalized:
        return []
    prefix = normalized + " "
    data = load_commands()
    completions: list[str] = []
    seen: set[str] = set()
    for entry in data.get("allowed_commands") or []:
        text = str(entry).strip()
        if not text or "*" in text:
            continue
        key = text.lower()
        if key.startswith(prefix) and key not in seen:
            seen.add(key)
            completions.append(text)
    return completions


def show_rejection_hint(command: str) -> str | None:
    """Name the command to use instead, when the allow/deny lists make that clear."""
    if _is_show_version_form(command):
        return (
            "On this device 'show version' is not a valid command; "
            "use 'show system information' (firmware, uptime, Config Save Status)."
        )
    if _is_config_dump_show(command):
        return (
            "Running and startup config are not available through the show tool; "
            "use config_read."
        )
    completions = _allowed_prefix_completions(command)
    if completions:
        forms = ", ".join(f"'{name}'" for name in completions)
        submitted = _normalized_show_command(command)
        return (
            f"'{submitted}' is not on the allowlist (bare prefixes have been "
            f"incomplete on this device). Allowed forms: {forms}."
        )
    return None


def rejected_show_message(command: str, reason: str) -> str:
    hint = show_rejection_hint(command)
    if hint:
        return f"Command rejected: {reason}. {hint}"
    return f"Command rejected: {reason}"


COMMAND_FILE_MISSING = "Error: NETMIKO_MCP_COMMAND_FILE is not set or the file does not exist."


def command_file_ready() -> bool:
    command_file = (os.environ.get("NETMIKO_MCP_COMMAND_FILE") or "").strip()
    return bool(command_file) and Path(command_file).expanduser().is_file()


def filter_commands(
    commands: list[str] | tuple[str, ...],
) -> tuple[list[tuple[str, str]], list[str]]:
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
            errors.append(
                f"{command}: {rejected_show_message(command, verdict.reason)}"
            )
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
    "rejected_show_message",
    "show_rejection_hint",
    "to_json",
    "with_audit_warning",
]
