"""Pure scorer. See architecture.md §10.

Shared by agent and engine so both run identical scoring. Pure function:
no I/O, no clock reads except via the injected Clock.
"""
from typing import Optional, Protocol

from common.matchers import evaluate_matcher
from common.schema import (
    Category, CheckResult, CollectorStatus, Evidence, Rubric, ScoreBreakdown,
)


class Clock(Protocol):
    """Timestamp for ScoreBreakdown.computed_at: box wall time in honor, the
    engine's authoritative receipt time in ranked. Never used for SLA accrual
    — that is engine/sla.py (§10.3)."""
    def now(self) -> float: ...


def evaluate(evidence: list, rubric: Rubric, clock: Clock) -> ScoreBreakdown:
    """Score point-in-time (non-SLA) rubric entries against collected evidence.

    Awards per category (§10.1): VULN points when matched; PENALTY negative
    points when the match FAILS; PROHIBITED negative points when it SUCCEEDS
    (`passed` = "requirement met", so a forbidden match passes=False). Entries
    with .sla are ignored here — engine/sla.py scores them statefully (§10.3).
    Missing/ERROR/TIMEOUT evidence scores "not satisfied" in every category:
    a collector fault is never a confirmed observation; the matcher still
    runs, only for an informative reason."""
    evidence_by_check_id = {e.check_id: e for e in evidence}

    results = []
    for entry in rubric.entries:
        if entry.sla is not None:
            continue

        ev: Optional[Evidence] = evidence_by_check_id.get(entry.check_id)
        raw = ev.raw if ev is not None else {}
        evidence_ok = ev is not None and ev.status == CollectorStatus.OK

        matched, matcher_reason = evaluate_matcher(entry.matcher, raw)

        if not evidence_ok:
            # Undetermined evidence is never a confirmed observation.
            awarded = 0
            matched = False
            passed = False
            matcher_reason = (
                f"evidence unavailable; scored as not satisfied ({matcher_reason})"
            )
        else:
            if entry.category == Category.PENALTY:
                awarded = entry.points if not matched else 0
                passed = matched
            elif entry.category == Category.PROHIBITED:
                awarded = entry.points if matched else 0
                # passed = "requirement met": a forbidden state present means
                # the requirement is NOT met, matcher True notwithstanding.
                passed = not matched
            else:
                awarded = entry.points if matched else 0
                passed = matched

        if ev is not None and ev.reason:
            reason = f"{matcher_reason} (evidence: {ev.reason})"
        else:
            reason = matcher_reason

        results.append(
            CheckResult(
                check_id=entry.check_id,
                category=entry.category,
                awarded_points=awarded,
                passed=passed,
                reason=reason,
            )
        )

    total = sum(r.awarded_points for r in results)

    return ScoreBreakdown(
        scenario_name=rubric.scenario_name,
        scenario_version=rubric.scenario_version,
        total=total,
        results=results,
        sla_status=[],
        computed_at=clock.now(),
    )
