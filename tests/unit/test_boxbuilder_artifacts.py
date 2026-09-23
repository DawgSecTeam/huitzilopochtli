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
    assert cfg["rubric_path"].endswith(f"/{artifacts.RUBRIC_BASENAME}")
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


def test_agent_config_notifications_roundtrip(tmp_path):
    """The notifications knob survives the disk roundtrip and defaults on for
    configs written before it existed (boxbuilder/agent version skew)."""
    from agent.config import load_config

    cfg = artifacts.agent_config_dict("demo", "honor")
    cfg["manifest_path"] = str(tmp_path / "manifest.json")
    cfg["rubric_path"] = str(tmp_path / "rubric.json")
    cfg["report_path"] = str(tmp_path / "report.html")
    path = tmp_path / "agent_config.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    assert load_config(str(path)).notifications is True

    # An older config without the key loads with notifications on.
    del cfg["notifications"]
    path.write_text(json.dumps(cfg), encoding="utf-8")
    assert load_config(str(path)).notifications is True

    cfg["notifications"] = False
    path.write_text(json.dumps(cfg), encoding="utf-8")
    assert load_config(str(path)).notifications is False


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
    for name in ("agent.pyz", "manifest.signed.json", "authoring_public_key.b64"):
        (ad / name).write_text("x")
    (ad / "rubric.json").write_text("{}")   # valid JSON: on_box_files encodes it
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
    assert any(r.endswith(f"/{artifacts.RUBRIC_BASENAME}") for r in remotes)
    assert any(r.endswith("/agent_config.json") for r in remotes)
    # agent_config.json was actually written to disk.
    written = json.loads((ad / "agent_config.json").read_text())
    assert written["mode"] == "honor"
    # sync-report.sh (mirrors report.html into $HOME/Documents/huitzilopochtli
    # for a snap-confined browser, and drops the legacy $HOME/Desktop copies) is
    # placed in both modes, executable.
    sync_files = [f for f in files if f.remote.endswith("/sync-report.sh")]
    assert len(sync_files) == 1
    assert sync_files[0].mode == 0o755
    sync_text = open(sync_files[0].local, encoding="utf-8").read()
    assert "Documents/huitzilopochtli" in sync_text
    assert "Desktop/report.html" in sync_text  # the legacy-cleanup rm targets


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
    # No rubric placed in ranked mode (stays off-box).
    assert not any(r.endswith(f"/{artifacts.RUBRIC_BASENAME}") for r in remotes)


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


def test_on_box_files_honor_rubric_encoded_0600(tmp_path):
    """The on-box rubric is the obfuscated .score.dat (0600), not plain
    rubric.json -- a cat/grep drive-by shouldn't hand over the answer key."""
    from common import rubric_codec

    ad = tmp_path / "artifacts"
    ad.mkdir()
    for name in ("agent.pyz", "manifest.signed.json", "authoring_public_key.b64"):
        (ad / name).write_text("x")
    rubric = {"schema_version": 1, "entries": [{"id": "ssh-root-login-disabled"}]}
    (ad / "rubric.json").write_text(json.dumps(rubric))
    compile_result = {
        "mode": "honor",
        "agent_pyz": str(ad / "agent.pyz"),
        "manifest": str(ad / "manifest.signed.json"),
        "authoring_public_key": str(ad / "authoring_public_key.b64"),
        "rubric": str(ad / "rubric.json"),
    }
    cfg = artifacts.agent_config_dict("demo", "honor")
    files = artifacts.on_box_files(compile_result, "honor", cfg)

    rubric_files = [f for f in files
                    if f.remote.endswith(f"/{artifacts.RUBRIC_BASENAME}")]
    assert len(rubric_files) == 1
    assert rubric_files[0].mode == 0o600
    with open(rubric_files[0].local, "rb") as f:
        raw = f.read()
    assert b"ssh-root-login" not in raw          # not greppable
    assert rubric_codec.decode_rubric(raw) == rubric
    # agent_config.json points at the new name too.
    written = json.loads((ad / "agent_config.json").read_text())
    assert written["rubric_path"] == f"{artifacts.INSTALL_DIR}/{artifacts.RUBRIC_BASENAME}"


# --- first-login motd banner --------------------------------------------------

def test_motd_script_honor_content():
    s = artifacts.motd_script("Opochtli Landing", "Harbor Port Authority", "honor")
    assert s.startswith("#!/bin/sh\n"), "motd fragment must be an executable sh script"
    assert "Welcome to Opochtli Landing — Harbor Port Authority" in s
    for cmd in ("huitz score", "huitz watch", "huitz forensics", "sudo huitz grade"):
        assert cmd in s, f"honor banner must teach {cmd}"
    assert "Forensics-Questions.txt" in s
    assert "ranked" not in s


def test_motd_script_leads_with_handbook_and_forensics_syntax():
    s = artifacts.motd_script("X", None, "honor")
    # A new player's first command is the handbook; it leads the list.
    assert s.index("huitz readme") < s.index("huitz score")
    assert "handbook" in s
    # The answer syntax is spelled out, not just the bare command.
    assert 'huitz forensics 1 "text"' in s


def test_motd_script_ranked_grade_line():
    s = artifacts.motd_script("X", None, "ranked")
    assert "sudo huitz grade" not in s, "ranked boxes cannot grade on-box"
    assert "scores arrive from the engine" in s


def test_motd_script_escapes_single_quotes():
    # A theme title with an apostrophe must survive the trip through the
    # single-quoted printf args — and run.
    import subprocess
    s = artifacts.motd_script("St. Mary's Hospital", None, "honor")
    run = subprocess.run(["sh", "-c", s], capture_output=True, text=True)
    assert run.returncode == 0, f"motd script does not run: {run.stderr}"
    assert "St. Mary's Hospital" in run.stdout


def test_motd_script_defaults_org_and_ends_with_newline():
    s = artifacts.motd_script("Only Title", None, "honor")
    assert "Welcome to Only Title" in s
    assert s.endswith("\n")
