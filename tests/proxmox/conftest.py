"""Load tests/proxmox/.env (if present) into os.environ, and auto-skip the
whole tests/proxmox/ tier when credentials aren't configured, so
`pytest -m proxmox` fails clearly and fast rather than erroring deep inside
a test. See tests/README.md.
"""
import os

import pytest
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

from tests.proxmox.proxmox_helper import proxmox_env_available  # noqa: E402

collect_ignore_glob = []

if not proxmox_env_available():
    collect_ignore_glob.append("test_*.py")


def pytest_collection_modifyitems(config, items):
    # This hook fires session-wide, not scoped to this directory -- only
    # mark items actually collected from within tests/proxmox/, or every
    # test in the whole suite gets deselected by the default
    # `-m "not proxmox"` addopts filter.
    here = str(__file__).rsplit("/", 1)[0]
    for item in items:
        if str(item.fspath).startswith(here):
            item.add_marker(pytest.mark.proxmox)
