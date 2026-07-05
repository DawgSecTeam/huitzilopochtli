"""Package-manager strategy (dpkg/rpm/apk). See architecture.md §9.3.

PHASE 1 TASK: implement package_installed(name) using whichever of
`dpkg -s`, `rpm -q`, `apk info -e` is present on the box. Shared by both
SystemdContext and OpenRCContext (package manager is orthogonal to init
system).
"""

import shutil
import subprocess


def _run(cmd: list):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=5)
    except (subprocess.TimeoutExpired, OSError):
        return None


def _dpkg_check(name: str) -> tuple:
    proc = _run(["dpkg", "-s", name])
    if proc is None or proc.returncode != 0:
        return (False, None)
    version = None
    for line in proc.stdout.splitlines():
        if line.startswith("Version:"):
            version = line.split(":", 1)[1].strip()
            break
    return (True, version)


def _rpm_check(name: str) -> tuple:
    proc = _run(["rpm", "-q", name])
    if proc is None or proc.returncode != 0:
        return (False, None)
    output = proc.stdout.strip()
    if not output:
        return (True, None)
    # best-effort: strip leading "<name>-" if present, else return raw output
    prefix = name + "-"
    version = output[len(prefix):] if output.startswith(prefix) else output
    return (True, version or None)


def _apk_check(name: str) -> tuple:
    proc = _run(["apk", "info", "-e", name])
    if proc is None or proc.returncode != 0 or not proc.stdout.strip():
        return (False, None)

    version = None
    info_proc = _run(["apk", "info", name])
    if info_proc is not None and info_proc.returncode == 0:
        for line in info_proc.stdout.splitlines():
            line = line.strip()
            if line.startswith(name + "-"):
                version = line
                break
    return (True, version)


def package_installed(name: str) -> tuple:
    """Returns (installed: bool, version: str | None)."""
    try:
        if shutil.which("dpkg"):
            return _dpkg_check(name)
        if shutil.which("rpm"):
            return _rpm_check(name)
        if shutil.which("apk"):
            return _apk_check(name)
        return (False, None)
    except Exception:
        return (False, None)
