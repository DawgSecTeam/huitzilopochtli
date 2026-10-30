import json

from engine.deploy import guard


def test_no_live_competition_allows_deploy(monkeypatch):
    monkeypatch.delenv("HUITZ_DEPLOY_FORCE", raising=False)
    assert guard.main(["guard", json.dumps({"live": 0})]) == 0


def test_live_competition_refuses_deploy(monkeypatch):
    monkeypatch.delenv("HUITZ_DEPLOY_FORCE", raising=False)
    assert guard.main(["guard", json.dumps({"live": 2})]) == 1


def test_force_allows_deploy_with_live_competition(monkeypatch):
    monkeypatch.setenv("HUITZ_DEPLOY_FORCE", "1")
    assert guard.main(["guard", json.dumps({"live": 1})]) == 0


def test_malformed_health_reads_as_zero():
    assert guard.live_count("not json") == 0
    assert guard.live_count(None) == 0
