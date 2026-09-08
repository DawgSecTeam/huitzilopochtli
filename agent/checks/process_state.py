"""`process_state` check type. See architecture.md §9.2.

collect_params: {"pattern": str} (regex).
Evidence.raw shape: {"running": bool, "count": int, "pids": list[int], "sample_cmdline": str|None}.

Detects whether a process matching `pattern` is currently running, by scanning
/proc directly -- pure stdlib, no subprocess, no platform layer (process
inspection via /proc is as distro-agnostic as the file/permission/user checks;
see architecture.md §9.3's "only the parts that actually differ... are
abstracted"). This exists to reward a team for finding and killing/removing a
live rogue process (simulated malware/C2), not just for removing the artifact
(cron entry, systemd unit, autostart file) that would have launched it.
"""
import os
import re
import time

from agent.checks.base import Check, register
from common.matchers import _compile_pattern
from common.schema import CheckSpec, CollectorStatus, Evidence

# Keep raw payloads small and bounded regardless of how many processes match.
_MAX_PIDS = 20
_SAMPLE_CMDLINE_LIMIT = 200


def _null_raw() -> dict:
    return {"running": False, "count": 0, "pids": [], "sample_cmdline": None}


def _read_cmdline(pid: str) -> str:
    """Return the process's cmdline as a space-joined string, or "" if
    unreadable/empty (kernel threads have an empty cmdline)."""
    with open(f"/proc/{pid}/cmdline", "rb") as f:
        raw = f.read()
    return raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()


def _read_comm(pid: str) -> str:
    with open(f"/proc/{pid}/comm", "r", errors="replace") as f:
        return f.read().strip()


def _process_haystack(pid: str) -> str:
    """The string a check pattern is matched against for one pid.

    cmdline is tried first and preferred: a shebang-launched payload (e.g.
    systemd `ExecStart=/opt/x/daemon` where daemon is a shell script) is
    kernel-exec'd as `/bin/sh /opt/x/daemon` -- `comm` truncates to just "sh"
    and never contains the disguised name, but cmdline does. Fall back to
    comm only when cmdline is empty/unreadable (e.g. kernel threads, or a
    process owned by another user whose cmdline is not world-readable but
    whose comm usually still is).
    """
    try:
        cmdline = _read_cmdline(pid)
        if cmdline:
            return cmdline
    except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
        pass
    try:
        return _read_comm(pid)
    except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
        return ""


@register("process_state")
class ProcessStateCheck(Check):
    type_key = "process_state"

    def collect(self, spec: CheckSpec, ctx) -> Evidence:
        pattern = spec.collect_params.get("pattern")
        if not pattern:
            return self._error(spec, "collect_params missing required 'pattern'")

        if not os.path.isdir("/proc"):
            return self._error(
                spec,
                "process_state requires a Linux /proc filesystem, "
                "not available on this platform",
            )

        try:
            compiled = _compile_pattern(pattern)
        except re.error as exc:
            return self._error(spec, f"invalid pattern {pattern!r}: {exc}")

        own_pid = str(os.getpid())
        matched_pids = []
        sample_cmdline = None
        capped = False

        try:
            entries = os.listdir("/proc")
        except OSError as exc:
            return self._error(spec, f"could not list /proc: {exc}")

        for entry in entries:
            if not entry.isdigit() or entry == own_pid:
                continue
            if len(matched_pids) >= _MAX_PIDS:
                capped = True
                break
            haystack = _process_haystack(entry)
            if not haystack:
                # Process vanished mid-scan, or neither cmdline nor comm was
                # readable -- routine under concurrent scanning, skip it.
                continue
            try:
                hit = compiled.search(haystack)
            except RecursionError:
                continue
            if hit:
                matched_pids.append(int(entry))
                if sample_cmdline is None:
                    sample_cmdline = haystack[:_SAMPLE_CMDLINE_LIMIT]

        running = bool(matched_pids)
        reason = (
            f"{len(matched_pids)} process(es) matched pattern {pattern!r}"
            if running
            else f"no running process matched pattern {pattern!r}"
        )
        if capped:
            reason += f" (list capped at {_MAX_PIDS})"

        return Evidence(
            check_id=spec.id,
            check_type=self.type_key,
            host_id=spec.host_id,
            status=CollectorStatus.OK,
            raw={
                "running": running,
                "count": len(matched_pids),
                "pids": matched_pids,
                "sample_cmdline": sample_cmdline,
            },
            reason=reason,
            collected_monotonic=time.monotonic(),
            collected_wall_claim=time.time(),
        )

    @staticmethod
    def _error(spec: CheckSpec, reason: str) -> Evidence:
        return Evidence(
            check_id=spec.id,
            check_type=ProcessStateCheck.type_key,
            host_id=spec.host_id,
            status=CollectorStatus.ERROR,
            raw=_null_raw(),
            reason=reason,
            collected_monotonic=time.monotonic(),
            collected_wall_claim=time.time(),
        )
