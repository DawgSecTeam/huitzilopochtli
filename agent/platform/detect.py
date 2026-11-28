"""Init-system detection. See architecture.md §9.3."""
import os
import sys

from agent.platform.base import PlatformContext


def detect() -> PlatformContext:
    """Detect the init system: win32 -> Windows (CIM), /run/systemd/system
    -> systemd, else OpenRC."""
    if sys.platform == "win32":
        from agent.platform.windows import WindowsContext
        return WindowsContext()
    if os.path.exists("/run/systemd/system"):
        from agent.platform.systemd import SystemdContext
        return SystemdContext()
    from agent.platform.openrc import OpenRCContext
    return OpenRCContext()
