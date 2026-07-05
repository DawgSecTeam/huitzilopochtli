"""systemd PlatformContext strategy. See architecture.md §9.3.

PHASE 1 TASK: implement using `systemctl is-active <svc>` / `systemctl
is-enabled <svc>` via subprocess, and agent.platform.pkg.package_installed
for packages.
"""
import subprocess

from agent.platform.base import PlatformContext
from agent.platform.pkg import package_installed as _package_installed


class SystemdContext(PlatformContext):
    def service_active(self, name: str) -> bool:
        try:
            result = subprocess.run(
                ["systemctl", "is-active", name],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

        return result.returncode == 0 and result.stdout.strip() == "active"

    def service_enabled(self, name: str) -> bool:
        try:
            result = subprocess.run(
                ["systemctl", "is-enabled", name],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

        return result.stdout.strip() == "enabled"

    def package_installed(self, name: str) -> tuple:
        return _package_installed(name)
