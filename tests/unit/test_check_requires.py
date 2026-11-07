"""The `requires` gate: a check cannot be graded without its software.

Field day (2026-11-06): a ranked agent bound to a host with no mail stack
scored "hardening 84" on Broadneck Post because collect scripts fail-opened
with `command -v postconf || { echo true; }`. Checks now declare optional
`requires` prerequisites; the collector evaluates them BEFORE running the
collect script and reports the third state `unavailable` (not solved, not
failed), which scores 0 and never counts as a pass anywhere.
"""
from common.evaluator import evaluate
from common.schema import (
    Category, CheckSpec, CollectorStatus, Rubric, RubricEntry,
)

import agent.collector as collector


class _Clock:
    def now(self):
        return 1_700_000_000.0


def _spec(**overrides):
    base = dict(
        id="smtp_configured",
        type="command_json",
        category=Category.VULN,
        host_id="localhost",
        collect_params={"script": "echo true"},
        display_title="The mailer is configured",
        display_max_points=5,
    )
    base.update(overrides)
    return CheckSpec(**base)


def _rubric():
    return Rubric(
        schema_version=1, scenario_name="sc", scenario_version=1,
        entries=[RubricEntry(
            check_id="smtp_configured",
            category=Category.VULN,
            matcher={"tag": "equals", "field": "data", "value": True},
            points=5,
        )],
    )


def test_missing_requires_yields_unavailable_and_zero_points():
    """The core fix: an absent prerequisite is `unavailable` and scores 0,
    even though the collect script itself would have echoed true."""
    spec = _spec(requires=["huitz-test-absent-binary-9f3c1a"])
    evidence = collector.run_all([spec], ctx=None)
    assert len(evidence) == 1
    ev = evidence[0]
    assert ev.status is CollectorStatus.UNAVAILABLE
    assert ev.raw == {}
    assert "huitz-test-absent-binary-9f3c1a not present" in ev.reason

    score = evaluate(evidence, _rubric(), _Clock())
    result = score.results[0]
    assert score.total == 0
    assert result.awarded_points == 0
    assert result.passed is False


def test_satisfied_requires_still_collects_and_scores():
    """Checks whose prerequisites exist behave exactly as before: the script
    runs, and a match still earns its points."""
    spec = _spec(requires=["sh", "/bin/sh"])
    ev = collector.run_all([spec], ctx=None)[0]
    assert ev.status is CollectorStatus.OK
    assert ev.raw["data"] is True
    assert evaluate([ev], _rubric(), _Clock()).total == 5


def test_score_cell_shows_ungraded_count():
    """The roster/leaderboard score cell names the ungraded checks; a clean
    row stays byte-identical to today's."""
    from engine.web import _score_cell

    broken = _score_cell({"total": 48, "hardening_points": 48,
                          "service_points": 0, "ungraded_count": 17})
    assert "17 checks ungraded: required software missing" in broken

    healthy = _score_cell({"total": 48, "hardening_points": 48,
                           "service_points": 0, "ungraded_count": 0})
    assert "ungraded" not in healthy
