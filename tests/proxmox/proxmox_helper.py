"""Shared helper for the tests/proxmox/ tier. See tests/README.md for the
setup this tier needs before it can run.

Not a copy of, or import from, workshop-vm-distribution -- that's a separate,
unrelated repo/tool. This reads its own local .env (gitignored) with the
same credential shape, so the two projects stay fully decoupled.

STATUS: scaffolding only. The env vars below are the exact ones needed;
test_local_honor_distribution.py and test_ranked_two_machines.py are not
yet written pending the setup details listed in tests/README.md (template
VM IDs, network bridge, credentials).
"""
import os

REQUIRED_ENV_VARS = (
    "PROXMOX_URL",
    "PROXMOX_USER",
    "PROXMOX_TOKEN_NAME",
    "PROXMOX_TOKEN_SECRET",
    "PROXMOX_NODE",
)

# Mirrors workshop-vm-distribution's own "workshop-" safety prefix so
# cleanup here can never touch an unrelated VM.
TEST_VM_PREFIX = "dawgtest-"


def proxmox_env_available() -> bool:
    """True if every required credential env var is set. Tests should
    pytest.skip(...) rather than fail when this is False, so the fast
    tiers stay green without this tier being configured."""
    return all(os.environ.get(key) for key in REQUIRED_ENV_VARS)


def get_proxmox_client():
    """Returns a proxmoxer.ProxmoxAPI client built from the env vars above.

    Raises RuntimeError with a clear message (listing tests/README.md's
    setup section) if proxmox_env_available() is False -- callers should
    check that first and skip instead of calling this.
    """
    if not proxmox_env_available():
        raise RuntimeError(
            "Proxmox credentials not configured; see tests/README.md's "
            "'tests/proxmox/ -- opt-in, live infrastructure required' "
            "section for the exact env vars needed."
        )
    from proxmoxer import ProxmoxAPI

    return ProxmoxAPI(
        os.environ["PROXMOX_URL"],
        user=os.environ["PROXMOX_USER"],
        token_name=os.environ["PROXMOX_TOKEN_NAME"],
        token_value=os.environ["PROXMOX_TOKEN_SECRET"],
        verify_ssl=False,
    )
