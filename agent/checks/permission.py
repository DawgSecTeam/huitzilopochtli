"""`permission` check type. See architecture.md §9.2.

PHASE 1 TASK: implement collect(). stat() of a path.
collect_params: {"path": str}.
Evidence.raw shape: {"mode": str (e.g. "0640"), "uid": int, "gid": int, "exists": bool}.
"""
from agent.checks.base import Check, register
from common.schema import CheckSpec, CollectorStatus, Evidence


@register("permission")
class PermissionCheck(Check):
    type_key = "permission"

    def collect(self, spec: CheckSpec, ctx) -> Evidence:
        raise NotImplementedError
