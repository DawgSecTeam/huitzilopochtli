"""OpenRC PlatformContext strategy. See architecture.md §9.3.

PHASE 1 TASK: implement using `rc-service <svc> status` / `rc-update show |
grep <svc>` via subprocess, and agent.platform.pkg.package_installed for
packages.
"""
from agent.platform.base import PlatformContext


class OpenRCContext(PlatformContext):
    def service_active(self, name: str) -> bool:
        raise NotImplementedError

    def service_enabled(self, name: str) -> bool:
        raise NotImplementedError

    def package_installed(self, name: str) -> tuple:
        raise NotImplementedError
