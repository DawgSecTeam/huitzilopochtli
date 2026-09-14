"""Windows PlatformContext strategy. See architecture.md §9.3.

Selected by agent.platform.detect when sys.platform == "win32". Mirrors the
systemd/OpenRC contract: best-effort, never raises -- a failed query reads as
False/(False, None) and the check-level evidence carries the error, so a
collector problem can never look like a satisfied check (fail closed).

Service state comes from CIM (Get-CimInstance Win32_Service): State maps to
active (== "Running") and StartMode maps to enabled (== "Auto", which covers
delayed-auto too; Manual/Disabled are not boot-started). Package presence
scans the HKLM uninstall keys (64- then 32-bit view).

Also hosts run_ps(), the shared stdlib-only PowerShell invocation used by the
Windows branches of the check modules (user_group, process_state) and the
powershell_json check. Output encoding is pinned to UTF-8 and captured text
is decoded leniently; scripts must emit their own JSON when parsed output is
wanted.
"""
import json
import subprocess

from agent.platform.base import PlatformContext

_PS_PREAMBLE = (
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
    "$ErrorActionPreference='SilentlyContinue'; "
)


def run_ps(script: str, timeout: float = 20) -> subprocess.CompletedProcess:
    """Run a read-only PowerShell snippet, leniently decoded. Raises only on
    timeout/OSError -- callers translate failures into check evidence."""
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive",
         "-ExecutionPolicy", "Bypass", "-Command", _PS_PREAMBLE + script],
        capture_output=True, text=True, errors="replace", timeout=timeout,
    )


def _ps_json(script: str, timeout: float = 20):
    """Run a snippet expected to emit JSON on stdout; None on any failure."""
    try:
        proc = run_ps(script, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return None
    out = (proc.stdout or "").strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except ValueError:
        return None


def _service_info(name: str):
    """{State, StartMode} for a service, or None when absent/unknowable."""
    if not name or "'" in name or '"' in name:
        return None
    script = (
        "$s = Get-CimInstance -ClassName Win32_Service "
        f"-Filter \"Name='{name}'\" | Select-Object -First 1; "
        "if ($s) { $s | Select-Object State,StartMode | ConvertTo-Json -Compress }"
    )
    info = _ps_json(script)
    return info if isinstance(info, dict) else None


def _package_installed(name: str) -> tuple:
    """Returns (installed: bool, version: str | None) from the HKLM
    uninstall keys (both registry views), matching DisplayName."""
    try:
        import winreg
    except ImportError:
        return (False, None)
    paths = [
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    wanted = name.casefold()
    for hive, path in paths:
        try:
            key = winreg.OpenKey(hive, path)
        except OSError:
            continue
        try:
            idx = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, idx)
                except OSError:
                    break
                idx += 1
                try:
                    sub = winreg.OpenKey(key, subkey_name)
                except OSError:
                    continue
                try:
                    display, _ = winreg.QueryValueEx(sub, "DisplayName")
                except OSError:
                    continue
                if isinstance(display, str) and display.casefold() == wanted:
                    try:
                        version, _ = winreg.QueryValueEx(sub, "DisplayVersion")
                        return (True, str(version))
                    except OSError:
                        return (True, None)
        finally:
            key.Close()
    return (False, None)


class WindowsContext(PlatformContext):
    def service_active(self, name: str) -> bool:
        info = _service_info(name)
        return info is not None and info.get("State") == "Running"

    def service_enabled(self, name: str) -> bool:
        info = _service_info(name)
        return info is not None and info.get("StartMode") == "Auto"

    def package_installed(self, name: str) -> tuple:
        return _package_installed(name)
