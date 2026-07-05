"""`user_group` check type. See architecture.md §9.2.

PHASE 1 TASK: implement collect(). Parses /etc/passwd, /etc/group.
collect_params: {} (or optional filters — see architecture.md; kept minimal).
Evidence.raw shape: {"users": list[str], "group_members": dict[str, list[str]]}.
Used for backdoor-user and wheel/sudo-membership checks.
"""
from agent.checks.base import Check, register
from common.schema import CheckSpec, CollectorStatus, Evidence


@register("user_group")
class UserGroupCheck(Check):
    type_key = "user_group"

    def collect(self, spec: CheckSpec, ctx) -> Evidence:
        raise NotImplementedError
