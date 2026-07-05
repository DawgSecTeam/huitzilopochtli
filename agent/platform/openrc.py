"""OpenRC PlatformContext strategy. See architecture.md §9.3.

PHASE 1 TASK: implement using `rc-service <svc> status` / `rc-update show |
grep <svc>` via subprocess, and agent.platform.pkg.package_installed for
packages.
"""
import subprocess

from agent.platform.base import PlatformContext
from agent.platform.pkg import package_installed as _package_installed


class OpenRCContext(PlatformContext):
    def service_active(self, name: str) -> bool:
        try:
            result = subprocess.run(
                ["rc-service", name, "status"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
        return "started" in result.stdout

    def service_enabled(self, name: str) -> bool:
        try:
            result = subprocess.run(
                ["rc-update", "show"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
        return name in result.stdout

    def package_installed(self, name: str) -> tuple:
        return _package_installed(name)
