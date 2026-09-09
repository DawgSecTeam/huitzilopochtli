"""Unit tests for packaging/rearm.py reset logic (architecture.md §17)."""
import importlib.util
import json
import os

# Load packaging/rearm.py BY FILE PATH: `from packaging import rearm` collides
# with the PyPI `packaging` namespace package in site-packages (same shadowing
# boxbuilder/pipeline.py works around). importlib by path is immune.
_REPO_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
_spec = importlib.util.spec_from_file_location(
    "huitzilopochtli.packaging.rearm",
    os.path.join(_REPO_ROOT, "packaging", "rearm.py"),
)
rearm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rearm)


def _write_config(tmp_path, identity_path):
    config_path = tmp_path / "agent_config.json"
    config = {
        "mode": "ranked",
        "manifest_path": str(tmp_path / "manifest.json"),
        "rubric_path": str(tmp_path / "rubric.json"),
        "identity_path": str(identity_path),
        "report_path": str(tmp_path / "report.html"),
        "checkin_interval_s": 30,
    }
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f)
    return config_path


def test_reset_identity_removes_enrolled_marker(tmp_path):
    # BUG-R1: --reset-identity removed identity + queue but NOT the `.enrolled`
    # marker, so the regenerated box_id/keypair skipped /enroll on next boot
    # and was rejected by the engine with 403 "unknown box" forever. reset
    # identity must clear the marker too.
    identity_path = tmp_path / "identity"
    identity_path.write_bytes(b"fake identity")
    (tmp_path / "identity.enrolled").write_bytes(b"1")
    (tmp_path / "identity.queue").write_text("bundle\n")

    config_path = _write_config(tmp_path, identity_path)

    actions = rearm.rearm(str(tmp_path), str(config_path), reset_identity=True)

    assert not (tmp_path / "identity.enrolled").exists(), \
        "rearm --reset-identity must remove the .enrolled marker"
    assert not identity_path.exists(), "identity file must be removed"
    assert not (tmp_path / "identity.queue").exists(), "queue must be removed"
    assert any("enrollment marker" in a for a in actions)


def test_rearm_without_reset_identity_preserves_marker(tmp_path):
    # Default rearm (a same-session retry) must NOT rotate identity: the
    # identity file and its .enrolled marker are preserved.
    identity_path = tmp_path / "identity"
    identity_path.write_bytes(b"fake identity")
    (tmp_path / "identity.enrolled").write_bytes(b"1")
    config_path = _write_config(tmp_path, identity_path)

    rearm.rearm(str(tmp_path), str(config_path), reset_identity=False)

    assert (tmp_path / "identity.enrolled").exists(), \
        "default rearm must not touch the enrollment marker"
    assert identity_path.exists(), "default rearm must not remove identity"


def test_rearm_removes_score_baseline(tmp_path):
    # The score baseline (agent/notify.py) lives next to the cached report;
    # leaving it behind would make the first post-rearm grade look like a
    # gain/loss against a stale session and fire a spurious alert.
    (tmp_path / "score_state.json").write_text('{"total": 50}')
    config_path = _write_config(tmp_path, tmp_path / "identity")

    actions = rearm.rearm(str(tmp_path), str(config_path), reset_identity=False)

    assert not (tmp_path / "score_state.json").exists(), \
        "rearm must remove the score baseline so the replay starts silent"
    assert any("score baseline" in a for a in actions)


def test_rearm_reports_missing_score_baseline(tmp_path):
    config_path = _write_config(tmp_path, tmp_path / "identity")
    actions = rearm.rearm(str(tmp_path), str(config_path), reset_identity=False)
    assert any("no score baseline" in a for a in actions)
