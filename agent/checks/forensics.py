"""`forensics_answer` check type. See architecture.md §9.2.

collect_params: {"path": str, "question_id": str, "ordinal": int}.
Evidence.raw shape: {"answer": str} — empty string when the question is
unanswered (blank line or the untouched ______ placeholder).

The answers file is team-editable; its format (one `Q<ordinal>:` block with
an `Answer:` line per question) lives in agent/answers.py, shared with the
template writer (agent/__main__.py) and the huitz CLI (agent/cli.py).
"""
import time

import agent.answers
from agent.checks.base import Check, register
from common.schema import CheckSpec, CollectorStatus, Evidence

# Cap read size — the answers file is team-editable (see agent/answers.py).
_CONTENT_LIMIT = agent.answers.CONTENT_LIMIT


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
        elif agent.answers.ANSWER_PLACEHOLDER_RE.match(answer):
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
        return agent.answers.extract_answer(content, ordinal)

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
