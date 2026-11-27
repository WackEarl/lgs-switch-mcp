"""save_config must not hang on a slow running-config dump.

The pre-save snapshot used to run ``show current running-config`` inside
the same session as ``save``, and ``save_config(dry_run=false)`` is not
wrapped in the call budget. A dump that outlives the caller then left
the SSH session open. These tests use FakeSwitch only; no live device.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from lgs_switch_mcp.connection import (
    SAVE_CONFIRM_ANSWER,
    SAVE_CONFIRM_RE,
    call_deadline,
    send_paged,
)
from lgs_switch_mcp.parser import prompt_end_regex, prompt_prefix
from lgs_switch_mcp.server import save_config
from tests.fakes import FakeSwitch, install
from tests.test_save_confirm import ScriptedChannel
from tests.test_server_tools import RUN_A, RUN_B
from tests.test_v032_retest import _slow

CONFIRM = (SAVE_CONFIRM_RE, SAVE_CONFIRM_ANSWER)


def test_save_accepts_lgs_building_configuration_ok() -> None:
    """Manual SSH on the LGS328PC: 'save' prints this and no Y/N prompt."""
    chan = ScriptedChannel(
        [["save\r\n", "Building configuration ...\r\n", "[OK]\r\n", "LGS328PC#"]]
    )
    out = send_paged(chan, "save", timeout=2, poll_interval=0, confirm=CONFIRM)
    assert chan.writes == ["save\n"]
    assert "Building configuration" in out
    assert "[OK]" in out


def test_save_accepts_ok_stuck_to_prompt() -> None:
    chan = ScriptedChannel([["save\r\n", "Building configuration ...\r\n[OK]LGS328PC#"]])
    out = send_paged(chan, "save", timeout=2, poll_interval=0, confirm=CONFIRM)
    assert chan.writes == ["save\n"]
    assert "[OK]" in out
    assert "LGS328PC#" not in out


def test_prompt_prefix_rejects_identifier_glue() -> None:
    class _Conn:
        base_prompt = "LGS328PC"

    end = prompt_end_regex(_Conn(), allow_prefix=True)
    assert prompt_prefix("LGS328PC#", end) == ""
    assert prompt_prefix("[OK]LGS328PC#", end) == "[OK]"
    assert prompt_prefix("  LGS328PC#", end) == "  "
    assert prompt_prefix("bannerLGS328PC#", end) is None


def test_save_config_pending_then_saves(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_PRE_WRITE_SNAPSHOT", "required")
    install(
        monkeypatch,
        FakeSwitch(
            {
                "show current running-config": _slow(RUN_B, 1.0),
                "show system information": "Config Save Status : Saved\n",
            }
        ),
    )
    saved: list[str] = []
    monkeypatch.setattr(
        "lgs_switch_mcp.server.save_in_session",
        lambda _c: saved.append("save") or "Saved",
    )
    started = time.monotonic()
    with call_deadline(2.5):
        first = save_config(dry_run=False)
    assert first.startswith("Pending: running-config dump still in progress")
    assert saved == []
    assert time.monotonic() - started < 2.0
    time.sleep(1.2)
    with call_deadline(5):
        result = json.loads(save_config(dry_run=False))
    assert saved == ["save"]
    assert result["sent"] is True
    assert result["device_output"] == "Saved"
    assert "system location B" in Path(result["backup"]["path"]).read_text(encoding="utf-8")


def test_save_config_snapshot_off_skips_slow_dump(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SWITCH_PRE_WRITE_SNAPSHOT", "off")
    dumped: list[str] = []

    def _dump() -> str:
        dumped.append("dump")
        time.sleep(5)
        return RUN_B

    install(
        monkeypatch,
        FakeSwitch(
            {
                "show current running-config": _dump,
                "show system information": "Config Save Status : Saved\n",
            }
        ),
    )
    saved: list[str] = []
    monkeypatch.setattr(
        "lgs_switch_mcp.server.save_in_session",
        lambda _c: saved.append("save") or "Saved",
    )
    started = time.monotonic()
    result = json.loads(save_config(dry_run=False))
    assert time.monotonic() - started < 1.0
    assert dumped == []
    assert saved == ["save"]
    assert result["sent"] is True
    assert result["backup"] == {"skipped": "SWITCH_PRE_WRITE_SNAPSHOT=off"}


def test_save_config_dry_run_pending_does_not_save(monkeypatch: pytest.MonkeyPatch) -> None:
    from lgs_switch_mcp import configstore

    configstore.store_backup(RUN_A, "running", tag="pre-save")
    install(
        monkeypatch,
        FakeSwitch(
            {
                "show current running-config": _slow(RUN_B, 1.0),
                "show system information": "Config Save Status : Not Saved\n",
            }
        ),
    )
    saved: list[object] = []
    monkeypatch.setattr("lgs_switch_mcp.server.save_in_session", saved.append)
    with call_deadline(2.5):
        first = save_config()
    assert first.startswith("Pending: running-config dump still in progress")
    assert saved == []
