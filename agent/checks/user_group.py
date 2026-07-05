"""`user_group` check type. See architecture.md §9.2.

PHASE 1 TASK: implement collect(). Parses /etc/passwd, /etc/group.
collect_params: {} (or optional filters — see architecture.md; kept minimal).
Evidence.raw shape: {"users": list[str], "group_members": dict[str, list[str]]}.
Used for backdoor-user and wheel/sudo-membership checks.
"""
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


@register("user_group")
class UserGroupCheck(Check):
    type_key = "user_group"

    def collect(self, spec: CheckSpec, ctx) -> Evidence:
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
