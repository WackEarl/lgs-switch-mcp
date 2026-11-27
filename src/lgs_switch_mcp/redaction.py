"""Fail-closed, line-based redaction of device text.

``redact_secrets`` (validation) replaces the exact secrets this server
knows (SSH password, configured SNMP community). This module adds a
second layer for secrets the server does not know: foreign SNMP
communities and security names, SNMPv3 auth/priv keys, ``username …
password …``, RADIUS/TACACS keys, key and certificate blocks.

Rules, applied line by line:

1. PEM-style blocks (``-----BEGIN … -----`` to ``-----END … -----``)
   are replaced by one ``[REDACTED-LINE]``. A block without an END
   line hides everything after BEGIN.
2. A line with a long key-like token (base64/hex, 40+ characters with
   letters and digits) becomes ``[REDACTED-LINE]``.
3. ``snmp community|targetparams|group|user …`` config lines keep
   only their keywords; every other token becomes ``[REDACTED]``. Any
   other ``snmp …`` line with an unknown sub-command becomes
   ``[REDACTED-LINE]``.
4. ``Label : value`` lines whose label names a secret (password, key,
   secret, community, auth, priv, security name, …) keep the value only
   if it is plain status vocabulary (Enabled, MD5, None, …); otherwise
   the value becomes ``[REDACTED]``.
5. ``password|secret|key <value…>`` masks everything after the keyword.
6. Any remaining line that still contains one of the sensitive words
   (``password|key|secret|community|auth|priv``) and was not handled by
   a rule above is removed and marked ``[REDACTED-LINE]``.

The functions are idempotent. Text produced by this server (headings,
JSON) is never passed through them; only device text is.
"""

from __future__ import annotations

import re

from lgs_switch_mcp.validation import redact_secrets

REDACTED = "[REDACTED]"
REDACTED_LINE = "[REDACTED-LINE]"

# Word-start matches: "auth" catches authentication/authkey, "priv" catches
# priv/privacy/private but not "privilege"; "key" only as a word or with a
# -/_ joint so that "monkey" or "Keller" in a description stay visible.
SENSITIVE_RE = re.compile(
    r"passw|secret|communit|\bkeys?\b|\bkey[-_]|[-_]keys?\b|\bauth|\bpriv(?!ilege)"
    r"|\bcert(?:ificate)?s?\b|\bcrypto\b",
    re.IGNORECASE,
)
# Labels that hold a secret on SNMP listings even without a sensitive word.
_LABEL_EXTRA_RE = re.compile(r"security\s*name|target\s*param", re.IGNORECASE)

# Phrases that contain a sensitive word but carry no secret.
_BENIGN_RE = re.compile(
    r"\b(?:un)?authori[sz]ed\b"
    r"|\bforce-?(?:un)?authori[sz]ed\b"
    r"|\bauthenticator\b"
    r"|\bauthentication(?:\s+(?:protocol|method|mode|type|status|state|port|"
    r"failures?|success(?:es)?|server|timeout|period|control|enabled|disabled))?\b"
    r"(?![-_ ]?keys?\b)"
    r"|\bauth[-_ ]?(?:mode|method|protocol|type|status|state|port|control)\b"
    r"|\bpriv(?:acy)?[-_ ]?(?:protocol|mode|type)\b"
    r"|\bnoauth\w*|\bauthnopriv\b|\bauthpriv\b"
    r"|\b(?:unknown|bad|illegal operation for)\s+community\s+names?(?:\s+supplied)?\b",
    re.IGNORECASE,
)

# Values that are status vocabulary, never a secret.
_SAFE_VALUE_TOKEN_RE = re.compile(
    r"^(?:enabled?|disabled?|none|yes|no|true|false|on|off|n/?a|-+|not|set|"
    r"configured|unconfigured|supported|unsupported|valid|invalid|active|inactive|"
    r"up|down|auto|both|local|radius|tacacs|primary|secondary|default|"
    r"md5|sha\d*|sha-\d+|des|3des|aes\d*|aes-?cfb-?\d*|hmac-?[a-z0-9-]+|cbc|ctr|"
    r"rsa|dsa|ecdsa|ssh-rsa|v[123]c?|noauth\w*|authnopriv|authpriv|auth|priv|"
    r"(?:un)?authori[sz]ed|force-?(?:un)?authori[sz]ed|\d+(?:\.\d+)*|"
    r"\[redacted\]|\[redacted-line\])$",
    re.IGNORECASE,
)

_LABEL_VALUE_RE = re.compile(r"^(\s*[A-Za-z][A-Za-z0-9 ./()_-]{0,60}?)(\s*:\s*|\s*:$)(.*)$")
_PEM_BEGIN_RE = re.compile(r"-{3,}\s*BEGIN [A-Z0-9 ]+-{3,}")
_PEM_END_RE = re.compile(r"-{3,}\s*END [A-Z0-9 ]+-{3,}")
_BLOB_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_-]{40,}")
_KEYWORD_VALUE_RE = re.compile(
    r"\b(password|passwd|secret|key|auth-key|priv-key|authkey|privkey)\b"
    r"(\s*[:=]\s*|\s+)\S.*$",
    re.IGNORECASE,
)
# "    0 Unknown community name" style statistic lines: a number, then words.
_COUNTER_LINE_RE = re.compile(r"^\s*\d+\s+[A-Za-z][A-Za-z /()-]*$")

_SNMP_CMD_RE = re.compile(r"^(\s*(?:no\s+)?snmp\s+)(\S+)(.*)$", re.IGNORECASE)
_SNMP_MASKED_KEYWORDS = {
    "community": {
        "index", "name", "security", "context", "contextengineid",
        "transporttag", "volatile", "nonvolatile",
    },
    "targetparams": {
        "user", "security-model", "message-processing", "v1", "v2c", "v3",
        "noauth", "auth", "priv", "volatile", "nonvolatile",
        "filterprofile-name", "filter-storagetype",
    },
    "group": {"user", "security-model", "v1", "v2c", "v3", "volatile", "nonvolatile"},
}
_SNMP_SAFE_SUBCOMMANDS = frozenset(
    {"view", "access", "notify", "agent", "filterprofile", "trap", "engineid", "proxy", "enable"}
)
_SNMP_USER_ALGORITHMS = frozenset(
    {"md5", "sha", "sha1", "des", "3des", "aes", "aes128", "aes192", "aes256",
     "aes_cfb128", "aes-cfb128", "aescfb128", "none"}
)


def _has_sensitive_word(line: str) -> bool:
    return bool(SENSITIVE_RE.search(_BENIGN_RE.sub(" ", line)))


def _has_blob(line: str) -> bool:
    for match in _BLOB_TOKEN_RE.finditer(line):
        token = match.group(0)
        if re.search(r"[A-Za-z]", token) and re.search(r"\d", token):
            return True
    return False


def _mask_snmp_tokens(head: str, sub: str, rest: str) -> str:
    keywords = _SNMP_MASKED_KEYWORDS[sub.lower()]
    out = [
        token if token.lower() in keywords or token == REDACTED else REDACTED
        for token in rest.split()
    ]
    return (head + sub + (" " + " ".join(out) if out else "")).rstrip()


def _mask_snmp_user(head: str, sub: str, rest: str) -> str:
    tokens = rest.split()
    if not tokens:
        return (head + sub).rstrip()
    out = [tokens[0]]  # the user name itself is not a secret
    expect_algorithm = False
    expect_key = False
    for token in tokens[1:]:
        lower = token.lower()
        if expect_algorithm:
            expect_algorithm = False
            if lower in _SNMP_USER_ALGORITHMS:
                out.append(token)
                expect_key = lower != "none"
                continue
        if expect_key:
            expect_key = False
            out.append(REDACTED)
            continue
        if lower in {"auth", "priv"}:
            out.append(token)
            expect_algorithm = True
            continue
        if lower in {"volatile", "nonvolatile"} or token == REDACTED:
            out.append(token)
            continue
        out.append(REDACTED)
    return head + sub + " " + " ".join(out)


def _redact_snmp_line(line: str) -> str | None:
    """Return the handled line for an ``snmp …`` config line, else None."""
    match = _SNMP_CMD_RE.match(line)
    if match is None:
        return None
    head, sub, rest = match.groups()
    lower = sub.lower()
    if lower in _SNMP_MASKED_KEYWORDS:
        return _mask_snmp_tokens(head, sub, rest)
    if lower == "user":
        return _mask_snmp_user(head, sub, rest)
    if lower in _SNMP_SAFE_SUBCOMMANDS and not _has_sensitive_word(rest):
        return line
    return REDACTED_LINE


def _redact_label_value(line: str) -> str | None:
    match = _LABEL_VALUE_RE.match(line)
    if match is None:
        return None
    label, sep, value = match.groups()
    if not (_has_sensitive_word(label) or _LABEL_EXTRA_RE.search(label)):
        return None
    tokens = [token for token in re.split(r"[\s,/]+", value.strip()) if token]
    if all(_SAFE_VALUE_TOKEN_RE.match(token) for token in tokens):
        return line
    return f"{label}{sep.rstrip()} {REDACTED}"


# Placeholders this server writes itself (e.g. "[REDACTED: unparseable …]").
_PLACEHOLDER_RE = re.compile(r"^\s*\[REDACTED(?:-LINE|:[^\]\n]*)?\]\s*$")
# Echo of a typed show command after the prompt (session logs).
_SHOW_ECHO_RE = re.compile(r"^[\w.-]+(?:\([\w-]+\))?[#>]\s*sh(?:o|ow)?\s+[\w .:/-]*$")


def _redact_line(line: str) -> str:
    if _PLACEHOLDER_RE.match(line):
        return line
    if _SHOW_ECHO_RE.match(line) and not _KEYWORD_VALUE_RE.search(line):
        return line
    if _has_blob(line):
        return REDACTED_LINE
    handled = _redact_snmp_line(line)
    if handled is not None:
        return handled
    handled = _redact_label_value(line)
    if handled is not None:
        return handled
    if _KEYWORD_VALUE_RE.search(line):
        return _KEYWORD_VALUE_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", line)
    if _COUNTER_LINE_RE.match(line):
        return line
    if _has_sensitive_word(line):
        return REDACTED_LINE
    return line


# One CLI help entry: a keyword, 2+ spaces, a description ("snmp   SNMP
# information"). Rule 3 would otherwise read "snmp <word>" as an SNMP
# config line with an unknown sub-command and hide it (live check 0.3.0).
_HELP_LINE_RE = re.compile(r"^\s*([a-z0-9][a-z0-9-]*)\s{2,}(\S.*)$", re.IGNORECASE)


def _is_safe_help_line(line: str) -> bool:
    """A help entry whose keyword and description hold no sensitive word and
    no key-like token. Anything else goes through the normal rules."""
    match = _HELP_LINE_RE.match(line)
    if match is None:
        return False
    return not (_has_sensitive_word(line) or _has_blob(line) or _KEYWORD_VALUE_RE.search(line))


def redact_sensitive_lines(text: str, *, strict: bool = False, help_listing: bool = False) -> str:
    """Apply the fail-closed line rules (see module docstring).

    ``strict=True`` (used for ``show radius …``) additionally removes every
    line that is not blank, a separator, or a ``Label : value`` line, so an
    unknown table layout cannot show a shared secret in a column.
    ``help_listing=True`` (show_help) keeps ``keyword  description`` lines
    that contain no sensitive word, instead of applying the SNMP rule to
    a ``snmp`` help entry; every other line is handled as usual.
    """
    if not text:
        return text
    out: list[str] = []
    in_block = False
    for line in text.split("\n"):
        if in_block:
            if _PEM_END_RE.search(line):
                in_block = False
            continue
        begin = _PEM_BEGIN_RE.search(line)
        if begin:
            out.append(REDACTED_LINE)
            in_block = not _PEM_END_RE.search(line[begin.end() :])
            continue
        if help_listing and _is_safe_help_line(line):
            out.append(line)
            continue
        redacted = _redact_line(line)
        if strict and redacted == line and line.strip():
            is_separator = bool(re.fullmatch(r"[\s\-=+|]+", line))
            if not is_separator and _LABEL_VALUE_RE.match(line) is None:
                redacted = REDACTED_LINE
        out.append(redacted)
    return "\n".join(out)


def redact_device_text(text: str, *, strict: bool = False, help_listing: bool = False) -> str:
    """Exact secret replacement first, then the fail-closed line rules."""
    return redact_sensitive_lines(redact_secrets(text), strict=strict, help_listing=help_listing)


__all__ = [
    "REDACTED",
    "REDACTED_LINE",
    "SENSITIVE_RE",
    "redact_device_text",
    "redact_sensitive_lines",
]
