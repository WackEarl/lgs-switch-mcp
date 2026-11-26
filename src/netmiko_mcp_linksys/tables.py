"""Best-effort parsers that turn LGS (ISS) show output into JSON-ready data.

The exact table layouts of the LGS328PC are not all live-confirmed, so
every parser is header-driven and tolerant: columns are found by their
header names, rows by a leading port token, and anything that cannot be
read is reported in ``warnings`` instead of being guessed. Parsers work
on already redacted text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_PORT_TOKEN_RE = re.compile(
    r"^(?:gi(?:gabitethernet)?|ge|eth(?:ernet)?)?\s*(?:\d+/)?(\d+)/(\d+)$", re.IGNORECASE
)
_PO_TOKEN_RE = re.compile(r"^(?:po|port-channel)\s*(\d+)$", re.IGNORECASE)
_SEPARATOR_RE = re.compile(r"^[\s\-=+|]*[-=]{2,}[\s\-=+|]*$")
_KV_RE = re.compile(
    r"^\s*([A-Za-z][A-Za-z0-9 ./()%_-]{0,60}?)\s*:\s+(.*?)\s*$"
    r"|^\s*([A-Za-z][A-Za-z0-9 ./()%_-]{0,60}?)\s*:\s*$"
)
_NUMBER_RE = re.compile(r"-?\d+(?:[.,]\d+)?")
_MAC_RE = re.compile(
    r"^(?:[0-9a-f]{2}([:-])[0-9a-f]{2}(?:\1[0-9a-f]{2}){4}|[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}|[0-9a-f]{12})$",
    re.IGNORECASE,
)


def normalize_port(token: str) -> str | None:
    """``Gi0/7``, ``gi 0/7``, ``GigabitEthernet0/7``, ``0/7`` -> ``0/7``; ``Po1`` -> ``po1``."""
    text = token.strip().rstrip(",")
    match = _PORT_TOKEN_RE.match(text)
    if match:
        return f"{int(match.group(1))}/{int(match.group(2))}"
    match = _PO_TOKEN_RE.match(text)
    if match:
        return f"po{int(match.group(1))}"
    return None


def normalize_mac(text: str) -> str | None:
    """Return ``aa:bb:cc:dd:ee:ff`` for the usual MAC spellings, else None."""
    value = text.strip()
    if not _MAC_RE.match(value):
        return None
    digits = re.sub(r"[^0-9a-fA-F]", "", value).lower()
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def header_key(text: str) -> str:
    """Normalize a column header: lower case, letters and digits only."""
    return re.sub(r"[^a-z0-9]", "", text.lower())


def to_number(text: str | None) -> int | float | None:
    """First number in ``text`` (``67.6 W`` -> 67.6, ``1,234`` -> 1234)."""
    if text is None:
        return None
    cleaned = text.replace(",", "") if re.fullmatch(r"[\d,]+", text.strip()) else text
    match = _NUMBER_RE.search(cleaned)
    if match is None:
        return None
    raw = match.group(0).replace(",", ".")
    return float(raw) if "." in raw else int(raw)


def parse_key_values(text: str) -> dict[str, str]:
    """``Label : value`` lines -> {label: value} (first occurrence wins)."""
    result: dict[str, str] = {}
    for line in text.splitlines():
        match = _KV_RE.match(line)
        if match is None:
            continue
        key = (match.group(1) or match.group(3) or "").strip()
        value = (match.group(2) or "").strip()
        if key and key not in result:
            result[key] = value
    return result


def find_value(values: dict[str, str], *needles: str) -> tuple[str, str] | None:
    """First (label, value) whose normalized label contains all needles."""
    keys = [header_key(needle) for needle in needles]
    for label, value in values.items():
        normalized = header_key(label)
        if all(key in normalized for key in keys):
            return label, value
    return None


@dataclass
class Table:
    headers: list[str]
    keys: list[str]
    rows: list[dict[str, str]] = field(default_factory=list)


def _column_starts_from_separator(line: str) -> list[int]:
    starts = []
    previous = " "
    for index, char in enumerate(line):
        if char in "-=" and previous not in "-=":
            starts.append(index)
        previous = char
    return starts


def _column_starts_from_header(line: str) -> list[int]:
    """Column starts from a header line: words separated by 2+ spaces form
    one column (``Mac Address``); without double spaces each word is one."""
    if re.search(r"\S\s{2,}\S", line):
        return [match.start() for match in re.finditer(r"\S+(?: \S+)*", line)]
    return [match.start() for match in re.finditer(r"\S+", line)]


def _slice(line: str, starts: list[int]) -> list[str]:
    cells = []
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else len(line)
        cells.append(line[start:end].strip() if start < len(line) else "")
    return cells


def _row_cells(line: str, starts: list[int]) -> list[str]:
    tokens = line.split()
    if len(tokens) == len(starts):
        return tokens
    cells = _slice(line, starts)
    # A value that spills left of its column start lands in the previous
    # cell; fixed-width slicing is still the best guess for such rows.
    return cells


def parse_tables(text: str) -> list[Table]:
    """Find header + separator tables (``Port  Status`` / ``----  ------``).

    A table ends at a blank line, a new separator, or a line that does not
    reach the first column. Multi-word headers are kept as one column.
    """
    lines = text.splitlines()
    tables: list[Table] = []
    index = 1
    while index < len(lines):
        line = lines[index]
        header = lines[index - 1]
        if _SEPARATOR_RE.match(line) and header.strip() and not _SEPARATOR_RE.match(header):
            starts = _column_starts_from_separator(line)
            if len(starts) >= 2:
                headers = [cell for cell in _slice(header, starts)]
            else:
                starts = _column_starts_from_header(header)
                headers = _slice(header, starts)
            keys = [header_key(cell) for cell in headers]
            table = Table(headers=headers, keys=keys)
            index += 1
            while index < len(lines):
                row = lines[index]
                if not row.strip() or _SEPARATOR_RE.match(row):
                    break
                if index + 1 < len(lines) and _SEPARATOR_RE.match(lines[index + 1]):
                    break  # next table's header
                cells = _row_cells(row, starts)
                table.rows.append(dict(zip(keys, cells, strict=False)))
                index += 1
            tables.append(table)
            continue
        index += 1
    return tables


def parse_header_table(text: str, required: tuple[str, ...]) -> list[Table]:
    """Tables with a separator line, or (fallback) a header line holding all
    ``required`` words followed by rows that start with a port token."""
    wanted = [header_key(word) for word in required]
    tables = [
        table
        for table in parse_tables(text)
        if all(any(want in key for key in table.keys) for want in wanted)
    ]
    if tables:
        return tables
    lines = text.splitlines()
    for index, line in enumerate(lines):
        normalized = header_key(line)
        if not all(want in normalized for want in wanted):
            continue
        starts = _column_starts_from_header(line)
        headers = _slice(line, starts)
        table = Table(headers=headers, keys=[header_key(cell) for cell in headers])
        for row in lines[index + 1 :]:
            if not row.strip():
                if table.rows:
                    break
                continue
            first = row.split()[0]
            if normalize_port(first) is None:
                if table.rows:
                    break
                continue
            table.rows.append(dict(zip(table.keys, _row_cells(row, starts), strict=False)))
        if table.rows:
            return [table]
    return []


def column(row: dict[str, str], *needles: str, exclude: tuple[str, ...] = ()) -> str | None:
    """Value of the first column whose key contains any needle (and no excluded word)."""
    for needle in needles:
        want = header_key(needle)
        for key, value in row.items():
            if want in key and not any(header_key(word) in key for word in exclude):
                return value
    return None


def row_port(row: dict[str, str]) -> str | None:
    for key in ("port", "interface", "intf", "localintf", "localport", "ports"):
        for column_key, value in row.items():
            if column_key == key or (key in column_key and "id" not in column_key):
                port = normalize_port(value.split()[0]) if value.split() else None
                if port:
                    return port
    first = next(iter(row.values()), "")
    return normalize_port(first.split()[0]) if first.split() else None


# ---------------------------------------------------------------- parsers


def parse_system_information(text: str) -> dict[str, Any]:
    values = parse_key_values(text)
    uptime = find_value(values, "up", "time") or find_value(values, "uptime")
    save = find_value(values, "save", "status") or find_value(values, "config", "save")
    return {
        "uptime": uptime[1] if uptime else None,
        "config_save_status": save[1] if save else None,
        "fields": values,
    }


def parse_power_detail(text: str) -> dict[str, Any]:
    values = parse_key_values(text)
    budget = (
        find_value(values, "budget")
        or find_value(values, "power", "available")
        or find_value(values, "nominal", "power")
        or find_value(values, "maximum", "power")
    )
    consumed = find_value(values, "consum") or find_value(values, "power", "used")
    return {
        "budget_w": to_number(budget[1]) if budget else None,
        "consumed_w": to_number(consumed[1]) if consumed else None,
        "fields": values,
    }


POE_MAX_PORT = 24
_BARE_PORT_RE = re.compile(r"^\d{1,2}$")


def normalize_poe_port(token: str) -> str | None:
    """Like normalize_port, plus the bare numbers ``1``..``24`` that
    ``show power inline`` prints in its Port column (-> ``0/N``)."""
    text = token.strip().rstrip(",")
    if _BARE_PORT_RE.match(text) and 1 <= int(text) <= POE_MAX_PORT:
        return f"0/{int(text)}"
    return normalize_port(text)


def _poe_row_port(row: dict[str, str]) -> str | None:
    for key, value in row.items():
        if key in {"port", "interface", "intf"} or key.startswith("port"):
            return normalize_poe_port(value.split()[0]) if value.split() else None
    first = next(iter(row.values()), "")
    return normalize_poe_port(first.split()[0]) if first.split() else None


def _poe_tables(text: str) -> list[Table]:
    """Tables of ``show power inline`` whose rows start with a port token
    (``Gi0/7``, ``0/7`` or a bare ``7``)."""
    found = [
        table for table in parse_tables(text)
        if any("port" in key for key in table.keys)
    ]
    if found:
        return found
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if "port" not in header_key(line) or not re.search(r"(?i)admin|oper|power", line):
            continue
        starts = _column_starts_from_header(line)
        headers = _slice(line, starts)
        table = Table(headers=headers, keys=[header_key(cell) for cell in headers])
        for row in lines[index + 1 :]:
            if not row.strip():
                if table.rows:
                    break
                continue
            if normalize_poe_port(row.split()[0]) is None:
                if table.rows:
                    break
                continue
            table.rows.append(dict(zip(table.keys, _row_cells(row, starts), strict=False)))
        if table.rows:
            return [table]
    return []


def parse_power_inline(text: str) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """``show power inline``: per port admin/status/W/class/priority.

    Live layout (LGS328PC): the Port column holds ``1``..``24`` and there
    are multi-word columns such as ``Power Limit Type`` and ``Auto Class``;
    their words must not be mistaken for the Power, Class or Type columns."""
    ports: dict[str, dict[str, Any]] = {}
    for table in _poe_tables(text):
        for row in table.rows:
            port = _poe_row_port(row)
            if port is None:
                continue
            power = column(
                row, "power(w)", "powerw", "outputpower", "power", "consum",
                exclude=("limit", "max", "prior", "type", "class", "budget"),
            )
            ports[port] = {
                "admin": column(row, "admin"),
                "status": column(row, "oper", "status", "state", exclude=("admin",)),
                "power_w": to_number(power),
                "max_power_w": to_number(column(row, "maxpower", "powerlimit", exclude=("type",))),
                "class": column(row, "class", exclude=("auto", "limit")),
                "auto_class": column(row, "autoclass"),
                "limit_type": column(row, "limittype", "powerlimittype"),
                "device": column(row, "device", "pdtype", exclude=("limit",)),
                "priority": column(row, "prior"),
            }
    warnings = [] if ports else ["show power inline: no port rows recognised"]
    return ports, warnings


_UP_WORDS = {"up", "connected", "linkup", "link-up"}
_DOWN_WORDS = {"down", "notconnected", "notconnect", "disabled", "linkdown", "err-disabled", "errdisabled"}


def link_state(value: str | None) -> str | None:
    if value is None:
        return None
    key = header_key(value)
    if key in {header_key(word) for word in _DOWN_WORDS} or key.startswith("not"):
        return "down"
    if key in {header_key(word) for word in _UP_WORDS}:
        return "up"
    return None


def parse_interfaces_status(text: str) -> tuple[dict[str, dict[str, Any]], list[str]]:
    ports: dict[str, dict[str, Any]] = {}
    for table in parse_header_table(text, ("port",)):
        for row in table.rows:
            port = row_port(row)
            if port is None:
                continue
            status = column(row, "status", "link", "state", exclude=("neg", "admin"))
            ports[port] = {
                "link": link_state(status),
                "status": status,
                "speed": column(row, "speed"),
                "duplex": column(row, "duplex"),
                "vlan": column(row, "vlan", "pvid"),
                "name": column(row, "name", "description"),
            }
    warnings = [] if ports else ["show interfaces status: no port rows recognised"]
    return ports, warnings


def parse_interface_counters(text: str) -> tuple[dict[str, dict[str, int | float | None]], list[str]]:
    """Merge every counters table (ISS prints an In table and an Out table)."""
    ports: dict[str, dict[str, int | float | None]] = {}
    for table in parse_header_table(text, ("port",)):
        for row in table.rows:
            port = row_port(row)
            if port is None:
                continue
            entry = ports.setdefault(port, {})
            for key, value in row.items():
                if key in {"port", "interface", "intf"}:
                    continue
                entry[key] = to_number(value)
    warnings = [] if ports else ["show interfaces counters: no port rows recognised"]
    return ports, warnings


def error_counters(counters: dict[str, int | float | None]) -> dict[str, int | float]:
    """Counters whose name contains err/discard/drop and whose value is > 0."""
    return {
        key: value
        for key, value in counters.items()
        if isinstance(value, (int, float))
        and value > 0
        and any(word in key for word in ("err", "discard", "drop"))
    }


def parse_interface_descriptions(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for table in parse_header_table(text, ("port",)) or parse_header_table(text, ("interface",)):
        for row in table.rows:
            port = row_port(row)
            if port is None:
                continue
            value = column(row, "description", "name", "alias")
            result[port] = value or ""
    return result


_VLAN_PORT_RE = re.compile(
    r"\b(?:gi(?:gabitethernet)?\s*)(\d+)/(\d+)(?:\s*-\s*(?:(?:gi(?:gabitethernet)?\s*)?(?:\d+/)?)(\d+))?",
    re.IGNORECASE,
)


def expand_port_list(text: str) -> list[str]:
    """``Gi0/1-4, Gi0/7`` -> [0/1, 0/2, 0/3, 0/4, 0/7]."""
    ports: list[str] = []
    for match in _VLAN_PORT_RE.finditer(text):
        slot, first, last = int(match.group(1)), int(match.group(2)), match.group(3)
        end = int(last) if last else first
        if end < first or end - first > 64:
            end = first
        ports.extend(f"{slot}/{number}" for number in range(first, end + 1))
    return ports


_VLAN_KV_ID_RE = re.compile(r"(?i)^\s*vlan\s*id\s*:\s*(\d{1,4})\s*$")
_VLAN_KV_FIELD_RE = re.compile(r"^\s*([A-Za-z][A-Za-z ]{0,40}?)\s*:\s*(.*)$")
_PO_LIST_RE = re.compile(r"\b(?:po|port-channel)\s*(\d+)\b", re.IGNORECASE)


def _port_list(text: str) -> list[str]:
    ports = expand_port_list(text)
    ports.extend(f"po{int(number)}" for number in _PO_LIST_RE.findall(text))
    return ports


def _parse_vlan_key_values(text: str) -> tuple[dict[str, list[dict[str, Any]]], list[str]]:
    """Live LGS layout: one block per VLAN with ``Vlan ID : 1``,
    ``Member Ports : Gi0/1, …``, ``Untagged Ports : …``; long port lists
    continue on indented lines without a label."""
    membership: dict[str, list[dict[str, Any]]] = {}
    warnings: list[str] = []
    blocks: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    field_name: str | None = None
    for line in text.splitlines():
        match = _VLAN_KV_ID_RE.match(line)
        if match:
            current = {"vlan": int(match.group(1)), "member": "", "untagged": "", "forbidden": ""}
            blocks.append(current)
            field_name = None
            continue
        if current is None:
            continue
        if not line.strip() or _SEPARATOR_RE.match(line):
            field_name = None
            continue
        field = _VLAN_KV_FIELD_RE.match(line)
        if field:
            label = header_key(field.group(1))
            field_name = None
            if label.startswith("member"):
                field_name = "member"
            elif label.startswith("untagged"):
                field_name = "untagged"
            elif label.startswith("forbidden"):
                field_name = "forbidden"
            elif label.startswith("tagged"):
                field_name = "tagged"
                current.setdefault("tagged", "")
            if field_name:
                current[field_name] += " " + field.group(2)
            continue
        if field_name and line[:1].isspace():
            current[field_name] += " " + line
    for block in blocks:
        vlan = block["vlan"]
        if not 1 <= vlan <= 4094:
            warnings.append(f"show vlan: VLAN id {vlan} out of range, skipped")
            continue
        members = _port_list(block["member"]) + _port_list(block.get("tagged", ""))
        untagged = set(_port_list(block["untagged"]))
        if not members and block["member"].strip() and block["member"].strip().lower() != "none":
            warnings.append(f"show vlan: member ports of VLAN {vlan} not recognised")
        for port in dict.fromkeys(members + sorted(untagged - set(members))):
            entries = membership.setdefault(port, [])
            item = {"vlan": vlan, "tagged": port not in untagged}
            if item not in entries:
                entries.append(item)
    if not blocks:
        warnings.append("show vlan: no 'Vlan ID' blocks recognised")
    return membership, warnings


def parse_vlan_membership(text: str) -> tuple[dict[str, list[dict[str, Any]]], list[str]]:
    """Best effort: ({port: [{vlan, tagged}]}, warnings) from ``show vlan``.

    The LGS prints key/value blocks (``Vlan ID : 1`` / ``Member Ports :``);
    a table layout (a line starting with a VLAN id opens a block, port
    lists on that line and following indented lines belong to it) is still
    understood. ``tagged`` is True/False when known, else None.
    """
    if any(_VLAN_KV_ID_RE.match(line) for line in text.splitlines()):
        return _parse_vlan_key_values(text)
    membership: dict[str, list[dict[str, Any]]] = {}
    current: int | None = None
    for line in text.splitlines():
        match = re.match(r"^\s*(\d{1,4})\b", line)
        if match and 1 <= int(match.group(1)) <= 4094 and not line.strip().startswith(("0/",)):
            current = int(match.group(1))
        elif not line.strip() or _SEPARATOR_RE.match(line):
            continue
        elif line[:1].strip() and not _VLAN_PORT_RE.search(line):
            # Unindented non-VLAN line: a new section (e.g. a header).
            current = None
        if current is None:
            continue
        lower = line.lower()
        tagged: bool | None = None
        if "untagged" in lower:
            tagged = False
        elif "tagged" in lower:
            tagged = True
        for port in expand_port_list(line):
            entries = membership.setdefault(port, [])
            if not any(item["vlan"] == current and item["tagged"] == tagged for item in entries):
                entries.append({"vlan": current, "tagged": tagged})
    warnings = [] if membership or not text.strip() else [
        "show vlan: no VLAN membership recognised"
    ]
    return membership, warnings


def parse_mac_table(text: str) -> tuple[list[dict[str, Any]], int | None, list[str]]:
    entries: list[dict[str, Any]] = []
    for table in parse_header_table(text, ("mac",)):
        for row in table.rows:
            mac_raw = column(row, "mac")
            mac = normalize_mac(mac_raw or "")
            if mac is None:
                continue
            port_raw = column(row, "port", "interface")
            entries.append(
                {
                    "vlan": to_number(column(row, "vlan")),
                    "mac": mac,
                    "type": column(row, "type", "status"),
                    "port": normalize_port(port_raw.split()[0]) if port_raw and port_raw.split() else None,
                }
            )
    if not entries:
        for line in text.splitlines():
            tokens = line.split()
            macs = [normalize_mac(token) for token in tokens]
            if not any(macs):
                continue
            mac = next(item for item in macs if item)
            ports = [normalize_port(token) for token in tokens]
            vlan = to_number(tokens[0]) if tokens and tokens[0].isdigit() else None
            entries.append(
                {"vlan": vlan, "mac": mac, "type": None, "port": next((p for p in ports if p), None)}
            )
    total = None
    match = re.search(r"(?i)total[^:\n]*:\s*(\d+)", text)
    if match:
        total = int(match.group(1))
    warnings = [] if entries or total == 0 else ["show mac-address-table: no entries recognised"]
    return entries, total, warnings


def parse_mac_count(text: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for label, value in parse_key_values(text).items():
        number = to_number(value)
        if isinstance(number, int):
            counts[label] = number
    if not counts:
        for line in text.splitlines():
            match = re.match(r"^\s*([A-Za-z][A-Za-z ()-]+?)\s{2,}(\d+)\s*$", line)
            if match:
                counts[match.group(1).strip()] = int(match.group(2))
    return counts


def parse_lldp_neighbors(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    neighbors: list[dict[str, Any]] = []
    for table in parse_header_table(text, ("local",)) or parse_header_table(text, ("device",)):
        for row in table.rows:
            local = column(row, "localintf", "localport", "local")
            port = normalize_port(local.split()[0]) if local and local.split() else row_port(row)
            if port is None:
                continue
            neighbors.append(
                {
                    "local_port": port,
                    "device_id": column(row, "deviceid", "systemname", "chassis", "device"),
                    "port_id": column(row, "portid", "remoteport"),
                    "capability": column(row, "capab"),
                    "hold_time": to_number(column(row, "hold", "ttl")),
                }
            )
    warnings = []
    if not neighbors and not re.search(r"(?i)total\s+entries\s+displayed\s*:\s*0\b", text):
        warnings.append("show lldp neighbors: no neighbor rows recognised")
    return neighbors, warnings


def parse_environment(text: str) -> dict[str, Any]:
    """Best effort for show device temperature / system fan / system
    utilization (layouts not recorded yet): ``Label : value`` pairs, else
    the table rows, else the first non-empty lines."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if lines and lines[0].startswith("%"):
        return {"unavailable": lines[0]}
    values = parse_key_values(text)
    if values:
        return {"fields": values}
    rows = [table.rows for table in parse_tables(text) if table.rows]
    if rows:
        return {"rows": [row for table_rows in rows for row in table_rows][:50]}
    return {"lines": lines[:20]}


_LOG_LINE_RE = re.compile(
    r"^\s*(?:<\d+>|\w{3}\s+\d{1,2}\s+\d{1,2}:\d{2}|\d{4}[-/]\d{2}[-/]\d{2}|\d{1,2}:\d{2}:\d{2})"
)


def parse_log_entries(text: str, limit: int = 10) -> list[str]:
    """Last ``limit`` lines that look like syslog entries (timestamp first)."""
    lines = [line.strip() for line in text.splitlines() if _LOG_LINE_RE.match(line)]
    return lines[-limit:] if limit > 0 else []


def interface_config_block(config: str, port: str) -> list[str]:
    """Lines of the ``interface gigabitethernet <port>`` block in a config."""
    lines = config.splitlines()
    block: list[str] = []
    inside = False
    for line in lines:
        stripped = line.strip()
        if re.match(r"(?i)^interface\s+", stripped):
            target = stripped.split(None, 1)[1] if len(stripped.split(None, 1)) > 1 else ""
            inside = normalize_port(target.replace(" ", "")) == port
            if inside:
                block.append(stripped)
            continue
        if inside:
            if stripped in {"!", "exit", "end"} or not stripped:
                inside = False
                continue
            block.append(stripped)
    return block


__all__ = [
    "Table",
    "column",
    "error_counters",
    "expand_port_list",
    "find_value",
    "header_key",
    "interface_config_block",
    "link_state",
    "normalize_mac",
    "normalize_poe_port",
    "normalize_port",
    "parse_environment",
    "parse_header_table",
    "parse_interface_counters",
    "parse_interface_descriptions",
    "parse_interfaces_status",
    "parse_key_values",
    "parse_lldp_neighbors",
    "parse_log_entries",
    "parse_mac_count",
    "parse_mac_table",
    "parse_power_detail",
    "parse_power_inline",
    "parse_system_information",
    "parse_tables",
    "parse_vlan_membership",
    "row_port",
    "to_number",
]
