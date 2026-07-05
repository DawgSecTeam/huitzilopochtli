"""Pure scorer. See architecture.md §10.

Lives here (not in agent/ or engine/) so honor-agent and engine run
IDENTICAL scoring logic. Must remain a pure function: no I/O, no clock
reads other than through the injected Clock.

PHASE 1 TASK: implement evaluate() per §10.1 using common.matchers.evaluate_matcher.
Do not change the function signature.
"""
from typing import Optional, Protocol

from common.matchers import evaluate_matcher
from common.schema import Category, CheckResult, Evidence, Rubric, ScoreBreakdown


class Clock(Protocol):
    """Supplies the timestamp stamped into ScoreBreakdown.computed_at.

    Honor mode: a trivial wrapper around time.time().
    Ranked mode: the engine's authoritative received_at for this check-in.
    Never used for SLA accrual — that lives entirely in engine/sla.py (§10.3).
    """
    def now(self) -> float: ...


# --- KNOWN SCHEMA GAP (flagged, not silently papered over) ------------------
#
# §10.1 defines three distinct scoring behaviors keyed by Category
# (VULN / PENALTY / PROHIBITED), but Category lives on CheckSpec (in the
# Manifest), NOT on RubricEntry (in the Rubric) — see common/schema.py.
# evaluate() is only given (evidence, rubric, clock), with no Manifest, so
# there is no way to recover the true Category for a given check_id here.
#
# Pragmatic convention used below (do not treat this as a permanent design
# decision — see the "open design question" flagged in the implementer's
# final report):
#   - entry.points >= 0  => treat as VULN-like: award points on matcher PASS.
#   - entry.points <  0  => treat as PENALTY/PROHIBITED-like. For PROHIBITED,
#     "award negative points when the forbidden state IS present" is
#     identical in shape to the VULN rule (award on matcher PASS), so the
#     default for negative-points entries is also "award on PASS".
#   - PENALTY is the one case that inverts this ("broken" == matcher FAILS).
#     Since Rubric/RubricEntry carries no Category, PENALTY entries must
#     opt in explicitly via `entry.matcher["penalty"] = True`. When that key
#     is truthy, points are awarded when the matcher's `matched` is False
#     instead of True.
#
# The CheckResult.category recorded is therefore also inferred, not looked
# up: Category.VULN for points >= 0, Category.PENALTY for points < 0 with
# matcher["penalty"] truthy, Category.PROHIBITED for points < 0 otherwise.
# This is a real gap: RubricEntry should probably carry an explicit
# `category: Category` field so this inference is never needed.


def _category_for(entry) -> Category:
    if entry.points >= 0:
        return Category.VULN
    if entry.matcher.get("penalty", False):
        return Category.PENALTY
    return Category.PROHIBITED


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

    NOTE: RubricEntry carries no Category (see the module-level comment
    above) — category is inferred from entry.points' sign plus an explicit
    `entry.matcher["penalty"]` opt-in flag for the PENALTY case. This is a
    pragmatic convention, flagged as an open design question.
    """
    evidence_by_check_id = {e.check_id: e for e in evidence}

    results = []
    for entry in rubric.entries:
        if entry.sla is not None:
            continue

        ev: Optional[Evidence] = evidence_by_check_id.get(entry.check_id)
        raw = ev.raw if ev is not None else {}

        matched, matcher_reason = evaluate_matcher(entry.matcher, raw)

        category = _category_for(entry)

        if category == Category.PENALTY:
            awarded = entry.points if not matched else 0
        else:
            # VULN and PROHIBITED both award on matcher PASS (§10.1; see
            # module-level comment on why PROHIBITED collapses into this
            # same rule given the frozen schema).
            awarded = entry.points if matched else 0

        if ev is not None and ev.reason:
            reason = f"{matcher_reason} (evidence: {ev.reason})"
        else:
            reason = matcher_reason

        results.append(
            CheckResult(
                check_id=entry.check_id,
                category=category,
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
