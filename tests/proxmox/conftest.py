"""Load tests/proxmox/.env (if present) into os.environ, and auto-skip the
whole tests/proxmox/ tier when credentials aren't configured, so
`pytest -m proxmox` fails clearly and fast rather than erroring deep inside
a test. See tests/README.md.
"""
import os

import pytest

try:
    from dotenv import load_dotenv
except ImportError:  # optional dev dependency; the fast tiers must not need it
    load_dotenv = None
if load_dotenv is not None:
    load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

from tests.proxmox.proxmox_helper import proxmox_env_available  # noqa: E402


def pytest_collection_modifyitems(config, items):
    # This hook fires session-wide, not scoped to this directory -- only
    # touch items actually collected from within tests/proxmox/, or every
    # test in the whole suite gets deselected by the default
    # `-m "not proxmox"` addopts filter.
    here = str(__file__).rsplit("/", 1)[0]
    available = proxmox_env_available()
    for item in items:
        if not str(item.fspath).startswith(here):
            continue
        item.add_marker(pytest.mark.proxmox)
        if not available:
            item.add_marker(pytest.mark.skip(
                reason="Proxmox credentials not configured (tests/proxmox/.env)"))
