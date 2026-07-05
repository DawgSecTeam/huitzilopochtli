"""Pure scorer. See architecture.md §10.

Lives here (not in agent/ or engine/) so honor-agent and engine run
IDENTICAL scoring logic. Must remain a pure function: no I/O, no clock
reads other than through the injected Clock.

PHASE 1 TASK: implement evaluate() per §10.1 using common.matchers.evaluate_matcher.
Do not change the function signature.
"""
from typing import Protocol

from common.schema import Evidence, Rubric, ScoreBreakdown


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
    raise NotImplementedError
