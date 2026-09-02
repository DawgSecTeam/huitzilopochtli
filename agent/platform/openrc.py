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
        # rc-update show emits one line per enabled service:
        #   "<service> | <runlevel> [<runlevel>...]"
        # Match the SERVICE NAME COLUMN exactly. A substring match
        # ("ssh" in "sshd") would false-positive and award points for a
        # service that is not the one actually enabled.
        for line in result.stdout.splitlines():
            if "|" in line:
                service = line.split("|", 1)[0].strip()
            else:
                # Defensive: some rc-update variants omit the "| runlevel"
                # column and just list service names -- first token is it.
                service = line.split()[0] if line.split() else ""
            if service == name:
                return True
        return False

    def package_installed(self, name: str) -> tuple:
        return _package_installed(name)
