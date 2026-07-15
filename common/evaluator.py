"""Pure scorer. See architecture.md §10.

Lives here (not in agent/ or engine/) so honor-agent and engine run
IDENTICAL scoring logic. Must remain a pure function: no I/O, no clock
reads other than through the injected Clock.

PHASE 1 TASK: implement evaluate() per §10.1 using common.matchers.evaluate_matcher.
Do not change the function signature.
"""
from typing import Optional, Protocol

from common.matchers import evaluate_matcher
from common.schema import (
    Category, CheckResult, CollectorStatus, Evidence, Rubric, ScoreBreakdown,
)


class Clock(Protocol):
    """Supplies the timestamp stamped into ScoreBreakdown.computed_at.

    Honor mode: a trivial wrapper around time.time().
    Ranked mode: the engine's authoritative received_at for this check-in.
    Never used for SLA accrual — that lives entirely in engine/sla.py (§10.3).
    """
    def now(self) -> float: ...


def evaluate(evidence: list, rubric: Rubric, clock: Clock) -> ScoreBreakdown:
    """Score point-in-time (non-SLA) rubric entries against collected evidence.

    For each non-SLA RubricEntry: match the corresponding Evidence.raw against
    entry.matcher, then award entry.points per category (§10.1):
      - VULN: award points (positive) if matched, else 0.
      - PENALTY: award points (negative) if the required state is broken
        (match fails), else 0.
      - PROHIBITED: award points (negative) if the forbidden state is present
        (match succeeds), else 0.

    SLA entries (rubric entry with .sla set) are ignored here entirely — they
    are scored statefully by engine/sla.py, never by this pure pass (§10.3).

    Missing/ERROR/TIMEOUT evidence is scored as "not satisfied" for VULN, and
    handled explicitly per matcher for PENALTY/PROHIBITED.
    """
    evidence_by_check_id = {e.check_id: e for e in evidence}

    results = []
    for entry in rubric.entries:
        if entry.sla is not None:
            continue

        ev: Optional[Evidence] = evidence_by_check_id.get(entry.check_id)
        raw = ev.raw if ev is not None else {}
        evidence_ok = ev is not None and ev.status == CollectorStatus.OK

        matched, matcher_reason = evaluate_matcher(entry.matcher, raw)

        if not evidence_ok and entry.category in (Category.PENALTY, Category.PROHIBITED):
            # Undetermined evidence (missing / ERROR / TIMEOUT) must NOT trigger a
            # penalty: a collector failure is not proof that the box's required
            # state is broken (PENALTY) or that a forbidden state is present
            # (PROHIBITED). Awarding the negative points here would punish the box
            # for a collector fault it didn't cause. Score 0 and say why. (VULN
            # already scores undetermined evidence as "not satisfied" → 0, which
            # is the correct fail-closed behavior for a positive-points check.)
            awarded = 0
            matcher_reason = f"evidence unavailable; penalty not applied ({matcher_reason})"
        elif entry.category == Category.PENALTY:
            awarded = entry.points if not matched else 0
        else:
            # VULN and PROHIBITED both award on matcher PASS (§10.1).
            awarded = entry.points if matched else 0

        if ev is not None and ev.reason:
            reason = f"{matcher_reason} (evidence: {ev.reason})"
        else:
            reason = matcher_reason

        results.append(
            CheckResult(
                check_id=entry.check_id,
                category=entry.category,
                awarded_points=awarded,
                passed=matched,
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
