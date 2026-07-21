"""`permission` check type. See architecture.md §9.2.

PHASE 1 TASK: implement collect(). stat() of a path.
collect_params: {"path": str}.
Evidence.raw shape: {"mode": str (e.g. "0640"), "uid": int, "gid": int, "exists": bool}.
"""
import os
import stat
import time

from agent.checks.base import Check, register
from common.schema import CheckSpec, CollectorStatus, Evidence


@register("permission")
class PermissionCheck(Check):
    type_key = "permission"

    def collect(self, spec: CheckSpec, ctx) -> Evidence:
        path = spec.collect_params.get("path")
        if path is None:
            # A malformed check spec missing the required 'path' param used to
            # raise KeyError here; the outer run_all would catch it as a generic
            # ERROR, but the reason would be opaque ("collection error: 'path'").
            # Return a structured ERROR with an actionable reason instead.
            return Evidence(
                check_id=spec.id,
                check_type=self.type_key,
                host_id=spec.host_id,
                status=CollectorStatus.ERROR,
                raw={"mode": None, "uid": None, "gid": None, "exists": None},
                reason="missing 'path' parameter in collect_params",
                collected_monotonic=time.monotonic(),
                collected_wall_claim=time.time(),
            )
        try:
            try:
                st = os.stat(path)
            except FileNotFoundError:
                return Evidence(
                    check_id=spec.id,
                    check_type=self.type_key,
                    host_id=spec.host_id,
                    status=CollectorStatus.OK,
                    raw={"mode": None, "uid": None, "gid": None, "exists": False},
                    reason="path does not exist",
                    collected_monotonic=time.monotonic(),
                    collected_wall_claim=time.time(),
                )

            mode_str = format(stat.S_IMODE(st.st_mode), "04o")
            raw = {
                "mode": mode_str,
                "uid": st.st_uid,
                "gid": st.st_gid,
                "exists": True,
            }
            reason = "mode {}, uid={}, gid={}".format(mode_str, st.st_uid, st.st_gid)
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
                raw={"mode": None, "uid": None, "gid": None, "exists": None},
                reason="collection error: {}".format(exc),
                collected_monotonic=time.monotonic(),
                collected_wall_claim=time.time(),
            )
