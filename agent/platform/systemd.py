"""systemd PlatformContext strategy. See architecture.md §9.3.

PHASE 1 TASK: implement using `systemctl is-active <svc>` / `systemctl
is-enabled <svc>` via subprocess, and agent.platform.pkg.package_installed
for packages.
"""
from agent.platform.base import PlatformContext


class SystemdContext(PlatformContext):
    def service_active(self, name: str) -> bool:
        raise NotImplementedError

    def service_enabled(self, name: str) -> bool:
        raise NotImplementedError

    def package_installed(self, name: str) -> tuple:
        raise NotImplementedError
