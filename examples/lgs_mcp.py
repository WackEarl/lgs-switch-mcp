#!/usr/bin/env python3
"""Thin shim kept for the old `python /config/netmiko/lgs_mcp.py` hub entry.

The intended installation path is the packaged entrypoint:

    uvx --from git+https://github.com/WackEarl/lgs-switch-mcp@v0.4.0 lgs-switch-mcp

The previous command name `netmiko-mcp-linksys` still works as a deprecated
alias. This file is not a standalone implementation. The `lgs-switch-mcp`
package must be installed in the same environment. For the older
`uv run --no-project --with ... python /config/netmiko/lgs_mcp.py` form, add:

    --with git+https://github.com/WackEarl/lgs-switch-mcp
"""

from __future__ import annotations

import sys
from pathlib import Path

_CANDIDATES = (
    Path("/workspace/lgs-switch-mcp/src"),
    Path("/workspace/netmiko-mcp-linksys/src"),
    Path(__file__).resolve().parent.parent.parent / "lgs-switch-mcp" / "src",
    Path(__file__).resolve().parent.parent.parent / "netmiko-mcp-linksys" / "src",
    Path(__file__).resolve().parent / "src",
)
for _src in _CANDIDATES:
    if _src.is_dir() and str(_src) not in sys.path:
        sys.path.insert(0, str(_src))
        break

from lgs_switch_mcp.server import main

if __name__ == "__main__":
    main()
