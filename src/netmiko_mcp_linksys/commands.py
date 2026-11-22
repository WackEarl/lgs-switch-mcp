"""CLI sequence builders for interface, PoE, and description changes."""

from __future__ import annotations

READBACK_INTERFACE = "show interfaces gigabitethernet {port}"
READBACK_POE = "show power inline gigabitethernet {port}"
READBACK_DESCRIPTION = "show interfaces description"


def build_admin_state_commands(port: str, enabled: bool) -> list[str]:
    return [
        f"interface gigabitethernet {port}",
        "no shutdown" if enabled else "shutdown",
    ]


def build_poe_commands(port: str, enabled: bool) -> list[str]:
    return [
        f"interface gigabitethernet {port}",
        "power inline enable" if enabled else "power inline disable",
    ]


def build_description_commands(port: str, text: str | None) -> list[str]:
    """Always quote the text: the LGS CLI takes only one word unquoted.

    validate_description() forbids quotes in the text, so quoting is safe.
    """
    if text is None:
        inner = "no description"
    else:
        inner = f'description "{text}"'
    return [
        f"interface gigabitethernet {port}",
        inner,
    ]
