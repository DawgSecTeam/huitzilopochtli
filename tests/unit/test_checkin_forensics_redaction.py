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
