"""Init-system detection. See architecture.md §9.3.

FROZEN mechanism; PHASE 1 implements the concrete PlatformContext subclasses
this dispatches to (agent/platform/systemd.py, agent/platform/openrc.py).
"""
import os

from agent.platform.base import PlatformContext


def detect() -> PlatformContext:
    """Detect the init system and return a ready PlatformContext.

    systemd: presence of /run/systemd/system.
    OpenRC: else, presence of /sbin/openrc or the `rc-status` binary.
    """
    if os.path.exists("/run/systemd/system"):
        from agent.platform.systemd import SystemdContext
        return SystemdContext()
    from agent.platform.openrc import OpenRCContext
    return OpenRCContext()
