"""`user_group` check type. See architecture.md §9.2.

Evidence.raw shape: {"users": list[str], "group_members": dict[str, list[str]]}.

POSIX parses /etc/passwd and /etc/group directly; Windows (os.name == "nt")
collects local users and group membership via PowerShell -- the raw shape is
identical so every user_group matcher works unchanged on both platforms.
"""
import os
import time

from agent.checks.base import Check, register
from common.schema import CheckSpec, CollectorStatus, Evidence


def _parse_passwd(path="/etc/passwd"):
    users = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split(":")
            if not fields or not fields[0]:
                continue
            users.append(fields[0])
    return users


def _parse_group(path="/etc/group"):
    group_members = {}
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split(":")
            if not fields or not fields[0]:
                continue
            name = fields[0]
            members = []
            if len(fields) >= 4 and fields[3]:
                members = [m for m in fields[3].split(",") if m]
            group_members[name] = members
    return group_members


# PowerShell emits one JSON document {"users": [...], "group_members": {...}}.
# Member names come back DOMAIN-qualified (or as orphan SIDs); the trailing
# segment after the last backslash is the usable account name, matching how
# the POSIX parser reports plain usernames. Unresolvable members are skipped.
_WINDOWS_COLLECT_SCRIPT = r"""
$users = @(Get-LocalUser | ForEach-Object { $_.Name })
$members = @{}
@(Get-LocalGroup) | ForEach-Object {
    $grp = $_.Name
    try {
        $m = @(Get-LocalGroupMember -Group $grp -ErrorAction Stop |
            ForEach-Object {
                if ($_.Name) { ($_.Name -split '\\')[-1] }
            } | Where-Object { $_ })
        $members[$grp] = $m
    } catch { $members[$grp] = @() }
}
[pscustomobject]@{ users = $users; group_members = $members } |
    ConvertTo-Json -Depth 4 -Compress
"""


def _collect_windows():
    """(users, group_members) via PowerShell, or raises on any failure."""
    import json

    from agent.platform.windows import run_ps
    proc = run_ps(_WINDOWS_COLLECT_SCRIPT, timeout=30)
    out = (proc.stdout or "").strip()
    if proc.returncode != 0 and not out:
        raise RuntimeError(f"powershell exited {proc.returncode}")
    if not out:
        raise RuntimeError("powershell produced no output")
    data = json.loads(out)
    users = data.get("users") or []
    group_members = data.get("group_members") or {}
    if not isinstance(users, list) or not isinstance(group_members, dict):
        raise RuntimeError("unexpected collector payload shape")
    return users, group_members


@register("user_group")
class UserGroupCheck(Check):
    type_key = "user_group"

    def collect(self, spec: CheckSpec, ctx) -> Evidence:
        if os.name == "nt":
            return self._collect_windows_evidence(spec)
        return self._collect_posix_evidence(spec)

    def _collect_windows_evidence(self, spec: CheckSpec) -> Evidence:
        try:
            users, group_members = _collect_windows()
        except Exception as exc:
            return Evidence(
                check_id=spec.id,
                check_type=self.type_key,
                host_id=spec.host_id,
                status=CollectorStatus.ERROR,
                raw={"users": None, "group_members": None},
                reason="windows user/group collection error: {}".format(exc),
                collected_monotonic=time.monotonic(),
                collected_wall_claim=time.time(),
            )
        return Evidence(
            check_id=spec.id,
            check_type=self.type_key,
            host_id=spec.host_id,
            status=CollectorStatus.OK,
            raw={"users": users, "group_members": group_members},
            reason="{} users, {} groups collected via PowerShell".format(
                len(users), len(group_members)
            ),
            collected_monotonic=time.monotonic(),
            collected_wall_claim=time.time(),
        )

    def _collect_posix_evidence(self, spec: CheckSpec) -> Evidence:
        try:
            try:
                users = _parse_passwd()
            except OSError as exc:
                return Evidence(
                    check_id=spec.id,
                    check_type=self.type_key,
                    host_id=spec.host_id,
                    status=CollectorStatus.ERROR,
                    raw={"users": None, "group_members": None},
                    reason="could not read /etc/passwd: {}".format(exc),
                    collected_monotonic=time.monotonic(),
                    collected_wall_claim=time.time(),
                )

            try:
                group_members = _parse_group()
            except OSError as exc:
                return Evidence(
                    check_id=spec.id,
                    check_type=self.type_key,
                    host_id=spec.host_id,
                    status=CollectorStatus.ERROR,
                    raw={"users": None, "group_members": None},
                    reason="could not read /etc/group: {}".format(exc),
                    collected_monotonic=time.monotonic(),
                    collected_wall_claim=time.time(),
                )

            raw = {"users": users, "group_members": group_members}
            reason = "{} users, {} groups parsed from /etc/passwd and /etc/group".format(
                len(users), len(group_members)
            )
            return Evidence(
                check_id=spec.id,
                check_type=self.type_key,
                host_id=spec.host_id,
                status=CollectorStatus.OK,
                raw=raw,
                reason=reason,
                collected_monotonic=time.monotonic(),
                collected_wall_claim=time.time(),
            )
        except Exception as exc:
            return Evidence(
                check_id=spec.id,
                check_type=self.type_key,
                host_id=spec.host_id,
                status=CollectorStatus.ERROR,
                raw={"users": None, "group_members": None},
                reason="collection error: {}".format(exc),
                collected_monotonic=time.monotonic(),
                collected_wall_claim=time.time(),
            )
