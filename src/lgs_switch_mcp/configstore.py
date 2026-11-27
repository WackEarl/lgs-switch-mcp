"""Masked config backups, diffs, and small JSON state files under /data.

Files are created with mode 0600 in directories with mode 0700. Only
already masked text is ever written here (see redaction).
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from lgs_switch_mcp.validation import ValidationError

DEFAULT_BACKUP_DIR = "/data/netmiko/backups"
DEFAULT_STATE_DIR = "/data/netmiko/state"
MAX_DIFF_LINES = 400
CONFIG_SOURCES = ("running", "startup")
_TAG_RE = re.compile(r"^[a-z0-9_-]{1,40}$")


def backup_dir() -> Path:
    return Path((os.environ.get("SWITCH_BACKUP_DIR") or DEFAULT_BACKUP_DIR).strip()).expanduser()


def state_dir() -> Path:
    return Path((os.environ.get("SWITCH_STATE_DIR") or DEFAULT_STATE_DIR).strip()).expanduser()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _private_dir(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


def _write_private(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)


def validate_source(source: str) -> str:
    if source not in CONFIG_SOURCES:
        raise ValidationError("source must be 'running' or 'startup'.")
    return source


def backup_name(source: str, *, tag: str | None = None, now: datetime | None = None) -> str:
    stamp = (now or datetime.now().astimezone()).strftime("%Y-%m-%d_%H%M")
    suffix = f"_{tag}" if tag else ""
    return f"{stamp}_{source}{suffix}.cfg"


def latest_backup(
    source: str, *, exclude: Path | None = None, tag: str | None = None
) -> Path | None:
    """Newest ``*_<source>*.cfg`` in the backup dir (by mtime, then name).

    With ``tag`` only ``*_<source>_<tag>.cfg`` (and its ``-N`` collision
    variants) count, e.g. the copies save_config stores (tag pre-save)."""
    directory = backup_dir()
    if not directory.is_dir():
        return None
    pattern = f"*_{source}_{tag}*.cfg" if tag else f"*_{source}*.cfg"
    exact = re.compile(rf"_{re.escape(source)}_{re.escape(tag)}(?:-\d+)?\.cfg$") if tag else None
    candidates = [
        path
        for path in directory.glob(pattern)
        if path.is_file()
        and (exclude is None or path != exclude)
        and (exact is None or exact.search(path.name))
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda path: (path.stat().st_mtime, path.name))


def unified_diff(before: str, after: str, *, before_label: str, after_label: str) -> str:
    lines = list(
        difflib.unified_diff(
            before.splitlines(),
            after.splitlines(),
            fromfile=before_label,
            tofile=after_label,
            lineterm="",
        )
    )
    if len(lines) > MAX_DIFF_LINES:
        hidden = len(lines) - MAX_DIFF_LINES
        lines = lines[:MAX_DIFF_LINES] + [f"... ({hidden} more diff lines not shown)"]
    return "\n".join(lines)


def store_backup(
    masked: str, source: str, *, tag: str | None = None, diff_same_tag: bool = False
) -> dict[str, Any]:
    """Write a masked config file and diff it against the previous backup
    (of the same source; with ``diff_same_tag`` of the same source and tag).

    Raises OSError when the directory or file cannot be written.
    """
    validate_source(source)
    if tag is not None and not _TAG_RE.fullmatch(tag):
        raise ValidationError(f"Invalid backup tag {tag!r}.")
    directory = _private_dir(backup_dir())
    previous = latest_backup(source, tag=tag if diff_same_tag else None)
    name = backup_name(source, tag=tag)
    path = directory / name
    counter = 1
    while path.exists():
        counter += 1
        path = directory / name.replace(".cfg", f"-{counter}.cfg")
    text = masked if masked.endswith("\n") else masked + "\n"
    _write_private(path, text)
    result: dict[str, Any] = {
        "path": str(path),
        "sha256": sha256_text(text),
        "lines": len(text.splitlines()),
        "previous": str(previous) if previous else None,
        "changed_since_previous": None,
        "diff": None,
    }
    if previous is not None:
        old = previous.read_text(encoding="utf-8", errors="replace")
        result["changed_since_previous"] = old != text
        result["diff"] = unified_diff(old, text, before_label=previous.name, after_label=path.name)
    return result


def read_state(name: str) -> dict[str, Any] | None:
    path = state_dir() / name
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def write_state(name: str, data: dict[str, Any]) -> Path:
    directory = _private_dir(state_dir())
    path = directory / name
    tmp = directory / f".{name}.tmp"
    if tmp.exists():
        tmp.unlink()
    _write_private(tmp, json.dumps(data, ensure_ascii=True, sort_keys=True))
    os.replace(tmp, path)
    return path


def clear_state(name: str) -> bool:
    path = state_dir() / name
    if path.is_file():
        path.unlink()
        return True
    return False


__all__ = [
    "CONFIG_SOURCES",
    "DEFAULT_BACKUP_DIR",
    "DEFAULT_STATE_DIR",
    "MAX_DIFF_LINES",
    "backup_dir",
    "backup_name",
    "clear_state",
    "latest_backup",
    "read_state",
    "sha256_text",
    "state_dir",
    "store_backup",
    "unified_diff",
    "validate_source",
    "write_state",
]
