"""`file_regex` check type. See architecture.md §9.2.

PHASE 1 TASK: implement collect(). Reads a text file, applies an extract
regex. collect_params: {"path": str, "extract": str (regex with one group)}.
Evidence.raw shape: {"matched": str | None, "present": bool}.
"""
from agent.checks.base import Check, register
from common.schema import CheckSpec, CollectorStatus, Evidence


@register("file_regex")
class FileRegexCheck(Check):
    type_key = "file_regex"

    def collect(self, spec: CheckSpec, ctx) -> Evidence:
        raise NotImplementedError
