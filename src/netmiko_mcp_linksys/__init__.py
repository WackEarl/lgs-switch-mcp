"""Deprecated import alias for ``lgs_switch_mcp``.

The Python package was renamed. This module re-exports the new package so
existing imports, including the hub shim ``lgs_mcp.py``, keep working.
"""

from __future__ import annotations

import sys
import warnings
from importlib import import_module

_NEW = "lgs_switch_mcp"
_MESSAGE = (
    "The 'netmiko_mcp_linksys' package has been renamed to 'lgs_switch_mcp'. "
    "This compatibility alias will be removed in a future release."
)

warnings.warn(_MESSAGE, DeprecationWarning, stacklevel=2)

_new_pkg = import_module(_NEW)
__version__ = _new_pkg.__version__
__all__ = list(getattr(_new_pkg, "__all__", ()))

_SUBMODULES = (
    "audit",
    "commands",
    "compat",
    "configdump",
    "configstore",
    "connection",
    "errors",
    "output",
    "parser",
    "readtools",
    "redaction",
    "server",
    "snmp_cli",
    "tables",
    "toolkit",
    "validation",
    "writes",
    "writetools",
)

for _name in _SUBMODULES:
    _mod = import_module(f"{_NEW}.{_name}")
    sys.modules[f"{__name__}.{_name}"] = _mod
    globals()[_name] = _mod


def __getattr__(name: str):
    return getattr(_new_pkg, name)


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(dir(_new_pkg)))
