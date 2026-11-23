"""The live ranked report must not reveal per-question forensics scoring."""
from types import SimpleNamespace

from common.schema import (
    Category, CheckResult, CollectorStatus, Evidence,
)
from engine.checkin import _redact_for_box


def _ev(check_id, check_type="command_json", reason=""):
    return Evidence(
        check_id=check_id, check_type=check_type, host_id="localhost",
        status=CollectorStatus.OK, raw={}, reason=reason,
        collected_monotonic=0.0, collected_wall_claim=0.0,
    )


def _score(*ids):
    return SimpleNamespace(results=[
        CheckResult(check_id=cid, category=Category.VULN,
                    awarded_points=4, passed=True, reason="matcher")
        for cid in ids
    ])


def _evidence():
    return {"fq-1": _ev("fq-1", "forensics_answer", "my answer"),
            "banner": _ev("banner", reason="my banner")}


def test_running_run_hides_forensics_results():
    score = _score("fq-1", "banner")
    _redact_for_box(score, _evidence(), hide_forensics=True)
    assert [r.check_id for r in score.results] == ["banner"]
    assert score.results[0].reason == "my banner"


def test_finished_run_reveals_forensics_results():
    score = _score("fq-1", "banner")
    _redact_for_box(score, _evidence(), hide_forensics=False)
    assert [r.check_id for r in score.results] == ["fq-1", "banner"]


def test_rubric_ids_drive_hiding_not_the_fq_prefix():
    # Ids are the author's own string; `fq-` is convention, not contract.
    # A rubric-derived forensics id without the prefix is still hidden live.
    score = _score("question-nine", "banner")
    _redact_for_box(score, _evidence(), hide_forensics=True,
                    forensics_ids={"question-nine"})
    assert [r.check_id for r in score.results] == ["banner"]


def test_redact_sends_rubric_titles_only_for_visible_results():
    """Ranked manifests ship generic display titles; the engine may send the
    real wording back only for results the box may already see (passed /
    incurred penalties) — never for failed checks."""
    passed = CheckResult(check_id="chk-001", category=Category.VULN,
                         awarded_points=4, passed=True, reason="m")
    failed = CheckResult(check_id="chk-002", category=Category.VULN,
                         awarded_points=0, passed=False, reason="m")
    score = SimpleNamespace(results=[passed, failed])
    _redact_for_box(score, {}, titles={"chk-001": "Real title one",
                                       "chk-002": "Secret end-state"})
    visible = score.results
    assert [r.check_id for r in visible] == ["chk-001"]
    assert visible[0].title == "Real title one"
    assert failed.title == ""


def test_redact_without_titles_leaves_title_empty():
    score = _score("banner")
    _redact_for_box(score, _evidence())
    assert score.results[0].title == ""
