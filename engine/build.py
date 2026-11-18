"""Engine build identity.

The deployment root is the directory that contains ``engine/``: a bundle
directory (as laid down by packaging/build_engine_bundle.py) or the engine VM's
install root. The bundle build writes ``build_info.json`` there at build time;
a git-based deploy writes the same file from the pulled checkout. The engine
reads it once at startup and reports it on the admin dashboard.

An absent or unreadable file is reported honestly as an unknown build — the
dev checkout is the normal case; the admin page still renders.
"""
import json
import os
import time

# Captured at import ~= process start; the dashboard shows it so an operator
# can tell "old code still running" from "restart happened".
STARTED_AT = time.time()

_CACHE = None


def read_build_info(root: str) -> dict:
    """Parse ``<root>/build_info.json``; never raises."""
    info = {"commit": None, "built_at": None, "source": None}
    try:
        with open(os.path.join(root, "build_info.json"), encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return info
    if isinstance(data, dict):
        for key in ("commit", "built_at", "source"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                info[key] = value.strip()
    return info


def build_info(root: str = None, *, refresh: bool = False) -> dict:
    """Deployment build info, read once per process.

    The deployment root is the parent of this file's package directory.
    """
    global _CACHE
    if _CACHE is not None and not refresh:
        return _CACHE
    if root is None:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    _CACHE = read_build_info(root)
    return _CACHE
