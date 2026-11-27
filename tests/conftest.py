"""Set env before netmiko-mcp settings and the package are imported."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
COMMANDS = EXAMPLES / "commands.yml"

os.environ.setdefault("NETMIKO_MCP_COMMAND_FILE", str(COMMANDS))
os.environ.setdefault("SWITCH_HOST", "192.0.2.10")
os.environ.setdefault("SWITCH_USER", "dummy-user")
os.environ.setdefault("SWITCH_PASSWORD", "dummy-password-not-real")
os.environ.setdefault("SWITCH_DEVICE_TYPE", "cisco_s300")
os.environ.setdefault("SWITCH_KNOWN_HOSTS", str(EXAMPLES / "known_hosts"))
os.environ.setdefault("SWITCH_PROTECTED_PORTS", "0/24,0/25")
# Pre-0.3.0 tests use fake sessions without a running-config; tests of the
# snapshot set it explicitly.
os.environ.setdefault("SWITCH_PRE_WRITE_SNAPSHOT", "off")
# Session reuse and the SSH cooldown are tested explicitly; other tests
# expect one fresh session per call and no cooldown between fakes.
os.environ.setdefault("SWITCH_SESSION_IDLE", "0")
os.environ.setdefault("SWITCH_COOLDOWN_BASE", "0")
os.environ.setdefault("SWITCH_LOGOUT_TIMEOUT", "0.5")


@pytest.fixture(autouse=True)
def _private_dirs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep backups and state of every test in its own tmp directory."""
    monkeypatch.setenv("SWITCH_BACKUP_DIR", str(tmp_path / "backups"))
    monkeypatch.setenv("SWITCH_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.delenv("SWITCH_CAUTION_PORTS", raising=False)
    monkeypatch.delenv("SWITCH_SYSLOG_ALLOWED", raising=False)
    from netmiko_mcp_linksys import configdump, connection

    configdump.reset()
    connection.reset_session_state()


@pytest.fixture
def commands_file() -> Path:
    return COMMANDS


@pytest.fixture
def reset_command_file(monkeypatch: pytest.MonkeyPatch) -> None:
    from netmiko_mcp_linksys.server import prepare_runtime

    monkeypatch.setenv("NETMIKO_MCP_COMMAND_FILE", str(COMMANDS))
    prepare_runtime()


@pytest.fixture
def audit_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "audit.log"
    monkeypatch.setenv("SWITCH_AUDIT_LOG", str(path))
    return path
