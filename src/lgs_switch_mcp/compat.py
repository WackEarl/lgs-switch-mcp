"""Backward-compatible entry points for the previous package name."""

from __future__ import annotations

import sys
import warnings


_MESSAGE = (
    "The 'netmiko-mcp-linksys' command has been renamed to 'lgs-switch-mcp'. "
    "This alias will be removed in a future release."
)


def deprecated_main() -> None:
    """Console-script alias that warns, then starts the server."""
    warnings.warn(_MESSAGE, DeprecationWarning, stacklevel=2)
    print(f"lgs-switch-mcp: warning: {_MESSAGE}", file=sys.stderr, flush=True)
    from lgs_switch_mcp.server import main

    main()
