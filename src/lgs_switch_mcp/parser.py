"""Pager-prompt detection and cleanup of switch CLI output."""

from __future__ import annotations

import re
from typing import Any

from lgs_switch_mcp.output import strip_controls as _strip_controls

# Pager prompts seen on ISS / Cisco-SMB style CLIs, e.g. "--More--",
# "-- More --", "--More-- (45%)", "More: <space>,  Quit: q ...",
# "<--- More --->", "Press any key to continue (Q to quit)".
PAGER_RE = re.compile(
    r"(?:"
    r"-{2,}\s*\(?\s*more\s*\)?\s*-{2,}(?:\s*\(\d{1,3}%\))?"
    r"|<-+\s*more\s*-+>"
    r"|more:\s*<space>(?:[^\r\n]*?<return>)?"
    r"|press any key to continue(?:\s*\([^()\r\n]{0,40}\))?"
    r")",
    re.IGNORECASE,
)
# Marks where a pager prompt was cut; blank lines right after it are erase
# leftovers (netmiko turns the pager's "\r    \r" into newlines).
PAGE_BREAK = "\ue000"
MAX_PAGES = 2000


def _prompt_body(conn: Any) -> str:
    """Regex body for the device prompt, without anchors."""
    base = getattr(conn, "base_prompt", None)
    if isinstance(base, str) and base.strip():
        return re.escape(base.strip()) + r"[^\r\n#>]*[#>]"
    return r"[\w.\-]+[^\r\n#>]*[#>]"


def prompt_regex(conn: Any) -> re.Pattern[str]:
    """Whole last line is the device prompt (no other text)."""
    return re.compile(r"^\s*" + _prompt_body(conn) + r"\s*$")


def prompt_end_regex(conn: Any, *, allow_prefix: bool = False) -> re.Pattern[str]:
    """Prompt at the end of the last visible line.

    ``allow_prefix=True`` also matches a prompt stuck to earlier output on
    the same line (e.g. ``[OK]hostname#`` after ``save``). The character
    before the prompt, if any, must not be part of an identifier, so a
    config token is not mistaken for the prompt.
    """
    body = _prompt_body(conn)
    if allow_prefix:
        return re.compile(
            r"^(?P<prefix>.*?)(?:^|(?<=[^A-Za-z0-9._-]))" + body + r"\s*$"
        )
    return re.compile(r"^(?P<prefix>\s*)" + body + r"\s*$")


def prompt_prefix(line: str, prompt_end: re.Pattern[str]) -> str | None:
    """Prefix before a trailing prompt, or None if the line is not a prompt."""
    match = prompt_end.search(line)
    if match is None:
        return None
    return match.group("prefix")


def visible_tail(raw: str) -> str:
    """Last unterminated line as the terminal would show it."""
    text = _strip_controls(raw).replace(PAGE_BREAK, "")
    line = text.rsplit("\n", 1)[-1]
    if "\r" in line:
        segments = [seg for seg in line.split("\r") if seg.strip()]
        line = segments[-1] if segments else ""
    return line


def clean_output(
    raw: str,
    command: str,
    prompt_re: re.Pattern[str],
    *,
    prompt_end: re.Pattern[str] | None = None,
) -> str:
    """Strip ANSI, control characters, pager prompts and their erase leftovers,
    the command echo, and the prompt.

    Blank lines directly before or after a page break are dropped
    (pager erase leftovers, including trailing blanks at the end of a
    page); blank lines elsewhere in the device output are kept.
    """
    text = _strip_controls(raw)
    text = PAGER_RE.sub("", text)
    text = text.replace("\r\n", "\n")
    lines: list[str] = []
    after_break = False
    for line in text.split("\n"):
        if PAGE_BREAK in line:
            line = line.replace(PAGE_BREAK, "")
            after_break = True
            while lines and not lines[-1].strip():
                lines.pop()
        if "\r" in line:
            segments = [seg for seg in line.split("\r") if seg.strip()]
            line = segments[-1] if segments else ""
        line = line.rstrip()
        if after_break:
            if not line.strip():
                continue
            after_break = False
        lines.append(line)
    while lines and not lines[0].strip():
        lines.pop(0)
    if lines and command.strip() and command.strip() in lines[0]:
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    if lines:
        prefix: str | None = None
        if prompt_end is not None:
            prefix = prompt_prefix(lines[-1], prompt_end)
        elif prompt_re.search(lines[-1]):
            prefix = ""
        if prefix is not None:
            if prefix.strip():
                lines[-1] = prefix.rstrip()
            else:
                lines.pop()
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines)
