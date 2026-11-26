"""SwitchConnectionError wrapping and public re-exports (#6)."""

from __future__ import annotations

import builtins
import socket
from unittest.mock import MagicMock, patch

import pytest
from netmiko.exceptions import NetmikoTimeoutException

from netmiko_mcp_linksys.commands import build_admin_state_commands
from netmiko_mcp_linksys.connection import (
    ConnectionError,
    SwitchConnectionError,
    clean_output,
    run_show,
)
from netmiko_mcp_linksys.errors import SwitchConnectionError as CanonicalError
from netmiko_mcp_linksys.parser import PAGE_BREAK, clean_output as parse_clean_output
from netmiko_mcp_linksys.validation import ValidationError


def test_switch_connection_error_does_not_shadow_builtin() -> None:
    assert CanonicalError is not builtins.ConnectionError
    assert issubclass(CanonicalError, RuntimeError)
    assert ConnectionError is CanonicalError
    assert SwitchConnectionError is CanonicalError


def test_public_names_still_importable_from_connection() -> None:
    assert clean_output is parse_clean_output
    assert build_admin_state_commands("0/3", False)[-1] == "shutdown"
    assert PAGE_BREAK == "\ue000"


@pytest.mark.parametrize(
    "exc",
    [
        socket.timeout("timed out talking to dummy-password-not-real"),
        OSError("connection refused dummy-password-not-real"),
        NetmikoTimeoutException("Timed-out reading channel dummy-password-not-real"),
    ],
    ids=["socket.timeout", "OSError", "NetmikoTimeoutException"],
)
def test_run_show_wraps_transport_errors(exc: BaseException) -> None:
    with patch(
        "netmiko_mcp_linksys.connection.ConnectHandler",
        side_effect=exc,
    ):
        with pytest.raises(SwitchConnectionError) as excinfo:
            run_show("show system information")
    assert "dummy-password-not-real" not in str(excinfo.value)
    assert excinfo.value.__cause__ is None


def test_missing_host_stays_validation_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SWITCH_HOST", raising=False)
    with pytest.raises(ValidationError, match="SWITCH_HOST"):
        run_show("show system information")


def test_session_reraises_switch_connection_error() -> None:
    conn = MagicMock()
    err = SwitchConnectionError("already redacted")
    with (
        patch("netmiko_mcp_linksys.connection.ConnectHandler", return_value=conn),
        patch(
            "netmiko_mcp_linksys.connection.send_paged_redacted",
            side_effect=err,
        ),
    ):
        with pytest.raises(SwitchConnectionError, match="already redacted") as excinfo:
            run_show("show system information")
    assert excinfo.value is err
    assert excinfo.value.__cause__ is None


def test_tools_still_refuse_protected_ports(monkeypatch: pytest.MonkeyPatch) -> None:
    from netmiko_mcp_linksys.writetools import poe_disable, port_disable

    monkeypatch.setenv("SWITCH_PROTECTED_PORTS", "0/10,0/24")
    with patch("netmiko_mcp_linksys.writes.run_in_session") as run:
        for port in ("0/10", "0/24"):
            admin = port_disable(port, dry_run=False)
            poe = poe_disable(port, dry_run=False)
            assert admin.startswith("Rejected:")
            assert poe.startswith("Rejected:")
            assert f"protected port {port}" in admin
            assert f"protected port {port}" in poe
    run.assert_not_called()
