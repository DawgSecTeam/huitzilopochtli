"""`file_regex` check type. See architecture.md §9.2.

PHASE 1 TASK: implement collect(). Reads a text file, applies an extract
regex. collect_params: {"path": str, "extract": str (regex with one group)}.
Evidence.raw shape: {"matched": str | None, "present": bool}.
"""
import re
import time

from agent.checks.base import Check, register
from common.schema import CheckSpec, CollectorStatus, Evidence


@register("file_regex")
class FileRegexCheck(Check):
    type_key = "file_regex"

    def collect(self, spec: CheckSpec, ctx) -> Evidence:
        path = spec.collect_params.get("path")
        pattern = spec.collect_params.get("extract")

        try:
            try:
                with open(path, "r", errors="replace") as f:
                    content = f.read()
            except OSError as exc:
                return Evidence(
                    check_id=spec.id,
                    check_type=spec.type,
                    host_id=spec.host_id,
                    status=CollectorStatus.ERROR,
                    raw={"matched": None, "present": False},
                    reason=f"file {path} not found or unreadable: {exc}",
                    collected_monotonic=time.monotonic(),
                    collected_wall_claim=time.time(),
                )

            match = re.search(pattern, content, re.MULTILINE)
            matched = match.group(1) if match else None

            if matched is not None:
                reason = f"matched: {matched}"
            else:
                reason = f"pattern not found in {path}"

            return Evidence(
                check_id=spec.id,
                check_type=spec.type,
                host_id=spec.host_id,
                status=CollectorStatus.OK,
                raw={"matched": matched, "present": True},
                reason=reason,
                collected_monotonic=time.monotonic(),
                collected_wall_claim=time.time(),
            )
        except Exception as exc:
            return Evidence(
                check_id=spec.id,
                check_type=spec.type,
                host_id=spec.host_id,
                status=CollectorStatus.ERROR,
                raw={"matched": None, "present": False},
                reason=f"unexpected error: {exc}",
                collected_monotonic=time.monotonic(),
                collected_wall_claim=time.time(),
            )
