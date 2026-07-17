"""Unit tests for common/evaluator.py (architecture.md §10.1).

Verifies the current award logic, which keys off RubricEntry.category
(an explicit Category enum) rather than the old point-sign-inference
convention. See common/evaluator.py module docstring / evaluate() docstring
for the authoritative rules being tested here.
"""
import pytest

from common.evaluator import evaluate
from common.schema import (
    Category,
    CollectorStatus,
    Evidence,
    Rubric,
    RubricEntry,
    SlaParams,
)


class FakeClock:
    """Injectable Clock returning a fixed sentinel value."""

    def __init__(self, value):
        self._value = value

    def now(self):
        return self._value


SENTINEL_TIME = 1234567.5


def make_evidence(check_id, raw, status=CollectorStatus.OK, reason=""):
    return Evidence(
        check_id=check_id,
        check_type="test",
        host_id="host-1",
        status=status,
        raw=raw,
        reason=reason,
        collected_monotonic=0.0,
        collected_wall_claim=0.0,
    )


def make_rubric(entries, scenario_name="scenario", scenario_version=1):
    return Rubric(
        schema_version=1,
        scenario_name=scenario_name,
        scenario_version=scenario_version,
        entries=entries,
    )


def equals_matcher(field="matched", value=True):
    return {"tag": "equals", "field": field, "value": value}


def test_vuln_awards_points_when_matcher_passes():
    entry = RubricEntry(
        check_id="vuln-1",
        category=Category.VULN,
        matcher=equals_matcher(value="present"),
        points=10,
    )
    evidence = [make_evidence("vuln-1", {"matched": "present"})]
    score = evaluate(evidence, make_rubric([entry]), FakeClock(SENTINEL_TIME))

    assert len(score.results) == 1
    result = score.results[0]
    assert result.passed is True
    assert result.awarded_points == 10
    assert result.category == Category.VULN


def test_vuln_awards_zero_when_matcher_fails():
    entry = RubricEntry(
        check_id="vuln-1",
        category=Category.VULN,
        matcher=equals_matcher(value="present"),
        points=10,
    )
    evidence = [make_evidence("vuln-1", {"matched": "absent"})]
    score = evaluate(evidence, make_rubric([entry]), FakeClock(SENTINEL_TIME))

    result = score.results[0]
    assert result.passed is False
    assert result.awarded_points == 0


def test_penalty_awards_zero_when_matcher_passes_state_intact():
    # PENALTY: matcher passing means the required state is intact -> no penalty.
    entry = RubricEntry(
        check_id="pen-1",
        category=Category.PENALTY,
        matcher=equals_matcher(value="intact"),
        points=-5,
    )
    evidence = [make_evidence("pen-1", {"matched": "intact"})]
    score = evaluate(evidence, make_rubric([entry]), FakeClock(SENTINEL_TIME))

    result = score.results[0]
    assert result.passed is True
    assert result.awarded_points == 0
    assert result.category == Category.PENALTY


def test_penalty_awards_points_when_matcher_fails_state_broken():
    # PENALTY: matcher failing means the required state is broken -> penalty
    # applied (entry.points, which is negative by authoring convention).
    entry = RubricEntry(
        check_id="pen-1",
        category=Category.PENALTY,
        matcher=equals_matcher(value="intact"),
        points=-5,
    )
    evidence = [make_evidence("pen-1", {"matched": "broken"})]
    score = evaluate(evidence, make_rubric([entry]), FakeClock(SENTINEL_TIME))

    result = score.results[0]
    assert result.passed is False
    assert result.awarded_points == -5


def test_prohibited_awards_points_when_matcher_passes_forbidden_present():
    entry = RubricEntry(
        check_id="proh-1",
        category=Category.PROHIBITED,
        matcher=equals_matcher(value="forbidden-thing"),
        points=-20,
    )
    evidence = [make_evidence("proh-1", {"matched": "forbidden-thing"})]
    score = evaluate(evidence, make_rubric([entry]), FakeClock(SENTINEL_TIME))

    result = score.results[0]
    assert result.passed is True
    assert result.awarded_points == -20
    assert result.category == Category.PROHIBITED


def test_prohibited_awards_zero_when_matcher_fails():
    entry = RubricEntry(
        check_id="proh-1",
        category=Category.PROHIBITED,
        matcher=equals_matcher(value="forbidden-thing"),
        points=-20,
    )
    evidence = [make_evidence("proh-1", {"matched": "something-else"})]
    score = evaluate(evidence, make_rubric([entry]), FakeClock(SENTINEL_TIME))

    result = score.results[0]
    assert result.passed is False
    assert result.awarded_points == 0


def test_sla_entry_is_skipped_entirely():
    sla_entry = RubricEntry(
        check_id="sla-1",
        category=Category.VULN,
        matcher=equals_matcher(),
        points=5,
        sla=SlaParams(interval_s=60, points_per_interval=1),
    )
    non_sla_entry = RubricEntry(
        check_id="vuln-1",
        category=Category.VULN,
        matcher=equals_matcher(value="present"),
        points=10,
    )
    evidence = [
        make_evidence("sla-1", {"matched": True}),
        make_evidence("vuln-1", {"matched": "present"}),
    ]
    score = evaluate(
        evidence, make_rubric([sla_entry, non_sla_entry]), FakeClock(SENTINEL_TIME)
    )

    check_ids = [r.check_id for r in score.results]
    assert "sla-1" not in check_ids
    assert check_ids == ["vuln-1"]


def test_missing_evidence_calls_matcher_with_empty_raw_dict():
    # Per evaluate()'s source: evidence_by_check_id.get(entry.check_id) returns
    # None when there's no matching Evidence, and `raw = ev.raw if ev is not
    # None else {}` -- so the matcher is invoked with raw={} (not skipped, not
    # raising). For an "equals" matcher this means the field lookup misses and
    # the matcher reports not-matched.
    entry = RubricEntry(
        check_id="missing-1",
        category=Category.VULN,
        matcher=equals_matcher(value="present"),
        points=10,
    )
    score = evaluate([], make_rubric([entry]), FakeClock(SENTINEL_TIME))

    assert len(score.results) == 1
    result = score.results[0]
    assert result.passed is False
    assert result.awarded_points == 0
    assert "missing field" in result.reason


def test_total_is_sum_of_awarded_points():
    entries = [
        RubricEntry(
            check_id="vuln-1",
            category=Category.VULN,
            matcher=equals_matcher(value="present"),
            points=10,
        ),
        RubricEntry(
            check_id="pen-1",
            category=Category.PENALTY,
            matcher=equals_matcher(value="intact"),
            points=-5,
        ),
        RubricEntry(
            check_id="proh-1",
            category=Category.PROHIBITED,
            matcher=equals_matcher(value="forbidden-thing"),
            points=-20,
        ),
    ]
    evidence = [
        make_evidence("vuln-1", {"matched": "present"}),  # +10
        make_evidence("pen-1", {"matched": "broken"}),  # -5 (state broken)
        make_evidence("proh-1", {"matched": "something-else"}),  # 0 (not present)
    ]
    score = evaluate(evidence, make_rubric(entries), FakeClock(SENTINEL_TIME))

    assert score.total == 10 + -5 + 0
    assert score.total == sum(r.awarded_points for r in score.results)


def test_computed_at_comes_from_injected_clock():
    entry = RubricEntry(
        check_id="vuln-1",
        category=Category.VULN,
        matcher=equals_matcher(value="present"),
        points=10,
    )
    score = evaluate(
        [make_evidence("vuln-1", {"matched": "present"})],
        make_rubric([entry]),
        FakeClock(SENTINEL_TIME),
    )

    assert score.computed_at == SENTINEL_TIME
    assert score.computed_at is SENTINEL_TIME


def test_sla_status_is_always_empty_list_from_evaluate():
    entry = RubricEntry(
        check_id="vuln-1",
        category=Category.VULN,
        matcher=equals_matcher(value="present"),
        points=10,
    )
    score = evaluate(
        [make_evidence("vuln-1", {"matched": "present"})],
        make_rubric([entry]),
        FakeClock(SENTINEL_TIME),
    )

    assert score.sla_status == []


def test_check_result_category_matches_rubric_entry_category_verbatim():
    entries = [
        RubricEntry(
            check_id="vuln-1",
            category=Category.VULN,
            matcher=equals_matcher(value="present"),
            points=10,
        ),
        RubricEntry(
            check_id="pen-1",
            category=Category.PENALTY,
            matcher=equals_matcher(value="intact"),
            points=-5,
        ),
        RubricEntry(
            check_id="proh-1",
            category=Category.PROHIBITED,
            matcher=equals_matcher(value="forbidden-thing"),
            points=-20,
        ),
    ]
    evidence = [
        make_evidence("vuln-1", {"matched": "present"}),
        make_evidence("pen-1", {"matched": "intact"}),
        make_evidence("proh-1", {"matched": "forbidden-thing"}),
    ]
    score = evaluate(evidence, make_rubric(entries), FakeClock(SENTINEL_TIME))

    by_id = {r.check_id: r for r in score.results}
    assert by_id["vuln-1"].category == Category.VULN
    assert by_id["pen-1"].category == Category.PENALTY
    assert by_id["proh-1"].category == Category.PROHIBITED

    # Confirm category is taken verbatim from the entry, not re-derived from
    # points sign (e.g. a positive-points PROHIBITED entry, which would be
    # authoring nonsense but the evaluator must not "fix" it by inference).
    weird_entry = RubricEntry(
        check_id="proh-weird",
        category=Category.PROHIBITED,
        matcher=equals_matcher(value="forbidden-thing"),
        points=20,  # positive, atypical for PROHIBITED, but category still wins
    )
    evidence2 = [make_evidence("proh-weird", {"matched": "forbidden-thing"})]
    score2 = evaluate(evidence2, make_rubric([weird_entry]), FakeClock(SENTINEL_TIME))
    result2 = score2.results[0]
    assert result2.category == Category.PROHIBITED
    assert result2.awarded_points == 20


# --- undetermined evidence must never award VULN points (BUG-E1) -----------
#
# A collector that returns status=ERROR/TIMEOUT may still leave a value in
# ev.raw that happens to satisfy the matcher. Before the fix, the evaluator
# ran the matcher against that raw and awarded full VULN points for a finding
# that was never confirmed present -- contradicting the module docstring
# ("Missing/ERROR/TIMEOUT evidence is scored as 'not satisfied' for VULN")
# and inflating the score. For all categories the awarded points must be 0
# when the evidence is undetermined, regardless of what the matcher says.


@pytest.mark.parametrize("bad_status", [CollectorStatus.ERROR, CollectorStatus.TIMEOUT])
def test_vuln_awards_zero_on_error_or_timeout_evidence_even_when_raw_matches(bad_status):
    entry = RubricEntry(
        check_id="vuln-1",
        category=Category.VULN,
        matcher=equals_matcher(value="present"),
        points=10,
    )
    # raw MATCHES, but the evidence status is not OK -> must NOT award points.
    evidence = [make_evidence("vuln-1", {"matched": "present"}, status=bad_status)]
    score = evaluate(evidence, make_rubric([entry]), FakeClock(SENTINEL_TIME))

    result = score.results[0]
    assert result.awarded_points == 0
    assert result.passed is False
    assert "not satisfied" in result.reason
    assert score.total == 0


@pytest.mark.parametrize("bad_status", [CollectorStatus.ERROR, CollectorStatus.TIMEOUT])
def test_penalty_and_prohibited_award_zero_on_undetermined_evidence(bad_status):
    # Penalty/prohibited already short-circuited to 0 on undetermined evidence
    # before the fix; this pins the behavior (no negative points for a fault
    # the box didn't cause) and guards the restructured branch.
    pen = RubricEntry("pen-1", Category.PENALTY, equals_matcher(value="intact"), -5)
    proh = RubricEntry(
        "proh-1", Category.PROHIBITED, equals_matcher(value="forbidden-thing"), -20
    )
    evidence = [
        make_evidence("pen-1", {"matched": "broken"}, status=bad_status),
        make_evidence("proh-1", {"matched": "forbidden-thing"}, status=bad_status),
    ]
    score = evaluate(evidence, make_rubric([pen, proh]), FakeClock(SENTINEL_TIME))
    by_id = {r.check_id: r for r in score.results}

    assert by_id["pen-1"].awarded_points == 0
    assert by_id["proh-1"].awarded_points == 0
    assert score.total == 0
