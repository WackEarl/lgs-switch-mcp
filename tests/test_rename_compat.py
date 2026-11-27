"""Backward-compatible names after the lgs-switch-mcp rename."""

from __future__ import annotations

import importlib
import subprocess
import sys
import warnings
from importlib.metadata import entry_points

import pytest

from lgs_switch_mcp import __version__
from lgs_switch_mcp.server import mcp


def test_mcp_server_name_is_renamed() -> None:
    assert mcp.name == "lgs-switch-mcp"


def test_distribution_name() -> None:
    from importlib.metadata import version

    assert version("lgs-switch-mcp") == __version__


def test_console_scripts() -> None:
    scripts = entry_points().select(group="console_scripts")
    names = {ep.name: ep.value for ep in scripts}
    assert names["lgs-switch-mcp"] == "lgs_switch_mcp.server:main"
    assert names["netmiko-mcp-linksys"] == "lgs_switch_mcp.compat:deprecated_main"


def test_legacy_import_is_deprecated_alias() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", DeprecationWarning)
        # Re-import in case an earlier test already loaded the alias.
        sys.modules.pop("netmiko_mcp_linksys", None)
        for name in list(sys.modules):
            if name.startswith("netmiko_mcp_linksys."):
                sys.modules.pop(name)
        pkg = importlib.import_module("netmiko_mcp_linksys")
        server = importlib.import_module("netmiko_mcp_linksys.server")

    assert pkg.__version__ == __version__
    assert server.mcp is mcp
    assert any("renamed to 'lgs_switch_mcp'" in str(item.message) for item in caught)


def test_deprecated_console_script_warns(capsys: pytest.CaptureFixture[str]) -> None:
    from lgs_switch_mcp.compat import _MESSAGE, deprecated_main
    from lgs_switch_mcp import server as server_mod

    called = {"n": 0}

    def fake_main() -> None:
        called["n"] += 1

    original = server_mod.main
    server_mod.main = fake_main  # type: ignore[method-assign]
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", DeprecationWarning)
            deprecated_main()
    finally:
        server_mod.main = original  # type: ignore[method-assign]

    assert called["n"] == 1
    assert any(_MESSAGE in str(item.message) for item in caught)
    err = capsys.readouterr().err
    assert "lgs-switch-mcp: warning:" in err
    assert "netmiko-mcp-linksys" in err


def test_legacy_module_entrypoint_is_callable() -> None:
    """python -m netmiko_mcp_linksys --help would start the server; just import."""
    sys.modules.pop("netmiko_mcp_linksys.__main__", None)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        importlib.import_module("netmiko_mcp_linksys.__main__")
