"""Fake switch for the 0.3.0 tool tests. Never opens a connection.

``FakeSwitch`` answers show commands from canned text (recorded-style
ISS output written for these tests) and records config sets. ``install``
patches the session helpers in every module that opens a session.
"""

from __future__ import annotations

from typing import Any

import pytest

PROMPT = "LGS328PC"


class FakeSwitch:
    def __init__(
        self,
        outputs: dict[str, Any] | None = None,
        *,
        reject: str | None = None,
    ) -> None:
        # command -> str, or list[str] consumed in order (last one repeats)
        self.outputs: dict[str, Any] = dict(outputs or {})
        self.reject = reject
        self.config_sets: list[list[str]] = []
        self.config_kwargs: list[dict[str, Any]] = []
        self.shows: list[str] = []
        self.sessions = 0
        self.base_prompt = PROMPT
        self.prompt_refreshed = False

    # netmiko-like surface used by _send_config
    def send_config_set(self, commands: list[str], **kwargs: Any) -> str:
        self.config_sets.append(list(commands))
        self.config_kwargs.append(kwargs)
        if self.reject and any(self.reject in command for command in commands):
            return "\n".join(commands) + "\n% Invalid input detected"
        return "\n".join(f"{PROMPT}(config)# {command}" for command in commands)

    def set_base_prompt(self) -> str:
        self.prompt_refreshed = True
        return self.base_prompt

    def show(self, command: str) -> str:
        self.shows.append(command)
        value = self.outputs.get(command)
        if value is None:
            return "% Invalid input detected at '^' marker."
        if isinstance(value, list):
            return value.pop(0) if len(value) > 1 else value[0]
        if callable(value):
            return value()
        return value

    @property
    def sent(self) -> list[str]:
        return [command for batch in self.config_sets for command in batch]


def install(monkeypatch: pytest.MonkeyPatch, switch: FakeSwitch) -> FakeSwitch:
    from netmiko_mcp_linksys import connection, readtools, server, writes, writetools
    from netmiko_mcp_linksys.connection import redact_show_output

    def fake_send_paged(_conn: Any, command: str, **_kwargs: Any) -> str:
        return switch.show(command)

    def fake_run_in_session(callback: Any, **_kwargs: Any) -> Any:
        switch.sessions += 1
        return callback(switch)

    def fake_sequence(commands: list[str]) -> list[tuple[str, str | None, str | None]]:
        switch.sessions += 1
        return [(c, redact_show_output(c, switch.show(c)), None) for c in commands]

    monkeypatch.setattr(connection, "send_paged", fake_send_paged)
    for module in (writes, writetools, readtools, server):
        if hasattr(module, "send_paged"):
            monkeypatch.setattr(module, "send_paged", fake_send_paged)
        if hasattr(module, "run_in_session"):
            monkeypatch.setattr(module, "run_in_session", fake_run_in_session)
    monkeypatch.setattr(readtools, "run_show_sequence", fake_sequence)
    return switch


RUNNING_CONFIG = """\
!
set switch-name LGS328PC
system location Default Location
username admin password 7 0123abcdSECRETHASH privilege 15
snmp community index old name OldSecretComm77 security none
snmp user ro_user auth sha AuthKeyValue99 priv aes PrivKeyValue99
snmp targetparams tp1 user v2sec security-model v2c message-processing v2c
radius-server host 192.0.2.50 key RadiusShared1
!
interface gigabitethernet 0/3
 description "Office"
 storm-control broadcast level 1000
!
interface gigabitethernet 0/15
 description "EoC Zigbee"
!
-----BEGIN CERTIFICATE-----
MIIBszCCARygAwIBAgIJAKeyMaterial
-----END CERTIFICATE-----
end
"""

SECRETS_IN_RUNNING = (
    "0123abcdSECRETHASH",
    "OldSecretComm77",
    "AuthKeyValue99",
    "PrivKeyValue99",
    "v2sec",
    "RadiusShared1",
    "MIIBszCCARygAwIBAgIJAKeyMaterial",
)
