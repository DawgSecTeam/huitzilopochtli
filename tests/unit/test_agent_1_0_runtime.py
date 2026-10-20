"""1.0 agent runtime contract tests: strict config, cache, lock, TLS classification."""
import json
import os

import pytest

import agent.__main__ as agent_main
from agent import runlock
from agent.config import load_config
from agent.snapshot import build_snapshot, snapshot_path_for
from common.schema import Manifest, Mode, ScoreBreakdown


def _config(tmp_path, **overrides):
    data = {
        "mode": "honor",
        "manifest_path": str(tmp_path / "manifest.json"),
        "rubric_path": str(tmp_path / "rubric.json"),
        "identity_path": None,
        "report_path": str(tmp_path / "report.html"),
        "checkin_interval_s": None,
    }
    data.update(overrides)
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data))
    return load_config(str(path))


@pytest.mark.parametrize("value", ["false", 1, "yes", []])
def test_config_booleans_must_be_real_booleans(tmp_path, value):
    with pytest.raises(ValueError, match="must be a JSON boolean"):
        _config(tmp_path, allow_unsigned_manifest=value)


def test_config_accepts_real_booleans(tmp_path):
    cfg = _config(tmp_path, allow_unsigned_manifest=True, notifications=False)
    assert cfg.allow_unsigned_manifest is True
    assert cfg.notifications is False


def test_runlock_is_exclusive_and_releases(tmp_path):
    path = str(tmp_path / "grade.lock")
    first = runlock.RunLock(path)
    second = runlock.RunLock(path)
    assert first.acquire() is True
    assert second.acquire() is False
    first.release()
    assert second.acquire() is True
    second.release()


def test_cached_ranked_response_survives_restart(tmp_path):
    cfg = _config(tmp_path)
    manifest = Manifest(
        schema_version=1, scenario_name="sc", scenario_version=1,
        mode=Mode.RANKED, engine_url="http://127.0.0.1:9",
        hosts=["localhost"], checks=[],
    )
    score = ScoreBreakdown(
        scenario_name="sc", scenario_version=1, total=42, results=[],
        sla_status=[], computed_at=123.0,
    )
    snap = build_snapshot(score, manifest, mode="ranked", agent_version="1.0.0",
                          delta=None, computed_at=123.0, server_time=123.0,
                          next_checkin_s=60)
    with open(snapshot_path_for(cfg.report_path), "w", encoding="utf-8") as f:
        json.dump(snap, f)
    cached = agent_main._cached_ranked_response(cfg, manifest)
    assert cached is not None
    assert cached.score.total == 42
    assert cached.next_checkin_s == 60


def test_cached_ranked_response_rejects_different_scenario(tmp_path):
    cfg = _config(tmp_path)
    manifest = Manifest(
        schema_version=1, scenario_name="sc", scenario_version=1,
        mode=Mode.RANKED, engine_url="http://127.0.0.1:9",
        hosts=["localhost"], checks=[],
    )
    score = ScoreBreakdown(scenario_name="other", scenario_version=1, total=1,
                           results=[], sla_status=[], computed_at=1.0)
    snap = build_snapshot(score, manifest, mode="ranked", agent_version="1.0.0",
                          delta=None, computed_at=1.0, server_time=1.0,
                          next_checkin_s=60)
    with open(snapshot_path_for(cfg.report_path), "w", encoding="utf-8") as f:
        json.dump(snap, f)
    assert agent_main._cached_ranked_response(cfg, manifest) is None
