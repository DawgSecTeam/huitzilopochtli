"""Unit tests for boxbuilder.artifacts: per-mode agent_config.json + file set."""
import json
import os

import pytest

from boxbuilder import artifacts


def test_honor_agent_config():
    cfg = artifacts.agent_config_dict("demo", "honor")
    # Exact shape per agent/config.py::AgentConfig for honor.
    assert cfg["mode"] == "honor"
    assert cfg["manifest_path"].endswith("/manifest.signed.json")
    assert cfg["authoring_public_key_path"].endswith("/authoring_public_key.b64")
    assert cfg["rubric_path"].endswith("/rubric.json")
    assert cfg["report_path"].endswith("/report.html")
    assert cfg["identity_path"] is None
    assert cfg["checkin_interval_s"] is None
    assert cfg["enrollment_token"] is None


def test_ranked_agent_config():
    cfg = artifacts.agent_config_dict("demo", "ranked",
                                      engine_url="https://e.example.org",
                                      checkin_interval_s=45,
                                      enrollment_token="tok123")
    # Ranked shape: rubric off-box, identity pointed at, interval + token set.
    assert cfg["mode"] == "ranked"
    assert cfg["rubric_path"] is None
    assert cfg["identity_path"].endswith("/identity.json")
    assert cfg["checkin_interval_s"] == 45
    assert cfg["enrollment_token"] == "tok123"


def test_ranked_requires_engine_url():
    with pytest.raises(ValueError, match="engine_url"):
        artifacts.agent_config_dict("demo", "ranked", checkin_interval_s=60)


def test_ranked_requires_positive_interval():
    with pytest.raises(ValueError, match="checkin_interval_s"):
        artifacts.agent_config_dict("demo", "ranked", engine_url="https://e", checkin_interval_s=0)


def test_unknown_mode_rejected():
    with pytest.raises(ValueError, match="mode"):
        artifacts.agent_config_dict("demo", "bogus")


def test_on_box_files_honor(tmp_path):
    # Synthesize a minimal compile_result pointing at files in artifacts_dir.
    ad = tmp_path / "artifacts"
    ad.mkdir()
    for name in ("agent.pyz", "manifest.signed.json", "authoring_public_key.b64", "rubric.json"):
        (ad / name).write_text("x")
    compile_result = {
        "mode": "honor",
        "agent_pyz": str(ad / "agent.pyz"),
        "manifest": str(ad / "manifest.signed.json"),
        "authoring_public_key": str(ad / "authoring_public_key.b64"),
        "rubric": str(ad / "rubric.json"),
    }
    cfg = artifacts.agent_config_dict("demo", "honor")
    files = artifacts.on_box_files(compile_result, "honor", cfg)
    remotes = sorted(f.remote for f in files)
    assert any(r.endswith("/agent.pyz") for r in remotes)
    assert any(r.endswith("/manifest.signed.json") for r in remotes)
    assert any(r.endswith("/authoring_public_key.b64") for r in remotes)
    assert any(r.endswith("/rubric.json") for r in remotes)
    assert any(r.endswith("/agent_config.json") for r in remotes)
    # agent_config.json was actually written to disk.
    written = json.loads((ad / "agent_config.json").read_text())
    assert written["mode"] == "honor"


def test_on_box_files_ranked_omits_rubric(tmp_path):
    ad = tmp_path / "artifacts"
    ad.mkdir()
    for name in ("agent.pyz", "manifest.signed.json", "authoring_public_key.b64", "engine_record.json"):
        (ad / name).write_text("x")
    compile_result = {
        "mode": "ranked",
        "agent_pyz": str(ad / "agent.pyz"),
        "manifest": str(ad / "manifest.signed.json"),
        "authoring_public_key": str(ad / "authoring_public_key.b64"),
        "rubric": None,
    }
    cfg = artifacts.agent_config_dict("demo", "ranked", engine_url="https://e",
                                      checkin_interval_s=60, enrollment_token="t")
    files = artifacts.on_box_files(compile_result, "ranked", cfg)
    remotes = [f.remote for f in files]
    # No rubric.json placed in ranked mode (stays off-box).
    assert not any(r.endswith("/rubric.json") for r in remotes)


def test_on_box_files_honor_requires_rubric(tmp_path):
    ad = tmp_path / "artifacts"
    ad.mkdir()
    compile_result = {
        "mode": "honor",
        "agent_pyz": str(ad / "agent.pyz"),
        "manifest": str(ad / "manifest.signed.json"),
        "authoring_public_key": str(ad / "authoring_public_key.b64"),
        "rubric": None,  # missing!
    }
    cfg = artifacts.agent_config_dict("demo", "honor")
    with pytest.raises(ValueError, match="rubric"):
        artifacts.on_box_files(compile_result, "honor", cfg)
