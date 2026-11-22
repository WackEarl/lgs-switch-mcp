"""Pager-prompt detection and cleanup of switch CLI output."""

from __future__ import annotations

import re
from typing import Any

from netmiko_mcp_linksys.output import strip_controls as _strip_controls

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


def prompt_regex(conn: Any) -> re.Pattern[str]:
    base = getattr(conn, "base_prompt", None)
    if isinstance(base, str) and base.strip():
        return re.compile(r"^\s*" + re.escape(base.strip()) + r"[^\r\n#>]*[#>]\s*$")
    return re.compile(r"^\s*[\w.\-]+[^\r\n#>]*[#>]\s*$")


def visible_tail(raw: str) -> str:
    """Last unterminated line as the terminal would show it."""
    text = _strip_controls(raw).replace(PAGE_BREAK, "")
    line = text.rsplit("\n", 1)[-1]
    if "\r" in line:
        segments = [seg for seg in line.split("\r") if seg.strip()]
        line = segments[-1] if segments else ""
    return line


def clean_output(raw: str, command: str, prompt_re: re.Pattern[str]) -> str:
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
    if lines and prompt_re.search(lines[-1]):
        lines.pop()
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines)
