"""`forensics_answer` check type. See architecture.md §9.2.

collect_params: {"path": str, "question_id": str, "ordinal": int}.
Evidence.raw shape: {"answer": str} — empty string when the question is
unanswered (blank line or the untouched ______ placeholder).

The answers file is team-editable; each question block is

    Q<ordinal>: <question text>
    Answer: <team's answer>

and the collector extracts the Answer line that follows the Q<ordinal> line
matching this check's ordinal.
"""
import re
import time

from agent.checks.base import Check, register
from common.schema import CheckSpec, CollectorStatus, Evidence

_ANSWER_PLACEHOLDER_RE = re.compile(r"^_+$")
_QUESTION_RE = re.compile(r"^Q(\d+):")
_ANSWER_RE = re.compile(r"^Answer:(.*)$", re.IGNORECASE)

# Cap read size — the answers file is team-editable (see common/matchers.py).
_CONTENT_LIMIT = 1_000_000  # 1 MB


@register("forensics_answer")
class ForensicsAnswerCheck(Check):
    type_key = "forensics_answer"

    def collect(self, spec: CheckSpec, ctx) -> Evidence:
        path = spec.collect_params.get("path")
        ordinal = spec.collect_params.get("ordinal")

        if path is None:
            return self._error(spec, "collect_params missing required 'path'")
        if not isinstance(ordinal, int) or isinstance(ordinal, bool) or ordinal < 1:
            return self._error(
                spec, f"collect_params 'ordinal' must be a positive integer, got {ordinal!r}"
            )

        try:
            with open(path, "r", errors="replace") as f:
                content = f.read(_CONTENT_LIMIT + 1)
            if len(content) > _CONTENT_LIMIT:
                return self._error(
                    spec, f"answers file {path} exceeds {_CONTENT_LIMIT} bytes; not evaluated"
                )
        except OSError as exc:
            return self._error(spec, f"answers file {path} not found or unreadable: {exc}")

        answer, found = self._extract_answer(content, ordinal)
        if not found:
            return self._error(
                spec, f"no question block Q{ordinal} found in {path}"
            )

        if answer is None:
            reason = f"Q{ordinal} in {path} is unanswered"
        elif _ANSWER_PLACEHOLDER_RE.match(answer):
            reason = f"Q{ordinal} in {path} still has the blank placeholder"
        else:
            reason = f"answer recorded for Q{ordinal} in {path}"

        return Evidence(
            check_id=spec.id,
            check_type=spec.type,
            host_id=spec.host_id,
            status=CollectorStatus.OK,
            raw={"answer": answer or ""},
            reason=reason,
            collected_monotonic=time.monotonic(),
            collected_wall_claim=time.time(),
        )

    @staticmethod
    def _extract_answer(content: str, ordinal: int) -> tuple:
        """Return (answer_or_None, found). Answer is the text on the Answer:
        line following the Q<ordinal> line, stripped; None when left blank."""
        lines = content.splitlines()
        current_ordinal = None
        found = False
        answer = None
        for line in lines:
            qmatch = _QUESTION_RE.match(line.strip())
            if qmatch:
                current_ordinal = int(qmatch.group(1))
                if current_ordinal == ordinal:
                    found = True
                continue
            if current_ordinal != ordinal:
                continue
            amatch = _ANSWER_RE.match(line.strip())
            if amatch:
                answer = amatch.group(1).strip() or None
                break
        return answer, found

    @staticmethod
    def _error(spec: CheckSpec, reason: str) -> Evidence:
        return Evidence(
            check_id=spec.id,
            check_type=spec.type,
            host_id=spec.host_id,
            status=CollectorStatus.ERROR,
            raw={"answer": ""},
            reason=reason,
            collected_monotonic=time.monotonic(),
            collected_wall_claim=time.time(),
        )
