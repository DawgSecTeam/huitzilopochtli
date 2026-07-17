"""`file_regex` check type. See architecture.md §9.2.

PHASE 1 TASK: implement collect(). Reads a text file, applies an extract
regex. collect_params: {"path": str, "extract": str (regex with one group)}.
Evidence.raw shape: {"matched": str | None, "present": bool}.
"""
import re
import time

from agent.checks.base import Check, register
from common.matchers import _REGEX_HAYSTACK_LIMIT, _compile_pattern
from common.schema import CheckSpec, CollectorStatus, Evidence

# ReDoS guard: stdlib `re` cannot be safely CPU-bounded from within a worker
# thread (signal.alarm needs the main thread; a thread join can't interrupt a
# C-level regex holding the GIL). Mitigate the realistic vector -- a huge file
# amplifying a sloppy trusted pattern -- by capping how much we read. Pattern
# validation + compile-caching come from common.matchers._compile_pattern.
_CONTENT_LIMIT = _REGEX_HAYSTACK_LIMIT  # 1 MB


@register("file_regex")
class FileRegexCheck(Check):
    type_key = "file_regex"

    def collect(self, spec: CheckSpec, ctx) -> Evidence:
        path = spec.collect_params.get("path")
        pattern = spec.collect_params.get("extract")

        if path is None:
            return self._error(spec, "collect_params missing required 'path'")
        if pattern is None:
            return self._error(spec, "collect_params missing required 'extract'")

        try:
            try:
                with open(path, "r", errors="replace") as f:
                    content = f.read(_CONTENT_LIMIT + 1)
                if len(content) > _CONTENT_LIMIT:
                    return self._error(
                        spec, f"file {path} exceeds {_CONTENT_LIMIT} bytes; not evaluated"
                    )
            except OSError as exc:
                return self._error(spec, f"file {path} not found or unreadable: {exc}")

            try:
                compiled = _compile_pattern(pattern)
            except re.error as exc:
                return self._error(spec, f"invalid extract regex {pattern!r}: {exc}")
            try:
                match = compiled.search(content)
            except RecursionError:
                return self._error(spec, f"extract regex {pattern!r} hit recursion limit")
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
            return self._error(spec, f"unexpected error: {exc}")

    @staticmethod
    def _error(spec: CheckSpec, reason: str) -> Evidence:
        return Evidence(
            check_id=spec.id,
            check_type=spec.type,
            host_id=spec.host_id,
            status=CollectorStatus.ERROR,
            raw={"matched": None, "present": False},
            reason=reason,
            collected_monotonic=time.monotonic(),
            collected_wall_claim=time.time(),
        )
