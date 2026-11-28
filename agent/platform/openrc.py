"""OpenRC PlatformContext strategy. See architecture.md §9.3."""
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
        # Compare the service NAME COLUMN exactly: a substring match would
        # score "ssh" as if "sshd" were enabled. Some variants omit the
        # "| runlevel" column — then the first token is the service.
        for line in result.stdout.splitlines():
            if "|" in line:
                service = line.split("|", 1)[0].strip()
            else:
                service = line.split()[0] if line.split() else ""
            if service == name:
                return True
        return False

    def package_installed(self, name: str) -> tuple:
        return _package_installed(name)
