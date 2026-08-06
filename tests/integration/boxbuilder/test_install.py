"""Integration tests for boxbuilder.pipeline.install_box (step 3), both modes.

Honor: drives install_box against a FakeHandle, asserts the right file set
lands (rubric included) and init is enabled.

Ranked: same, but with engine.upload_scenario / mint_enrollment_token patched
to stubs (the real-engine interaction is covered by test_engine_client.py),
asserting rubric is NOT placed and the enrollment token lands in agent_config.json.
"""
import json
import os

import pytest

from boxbuilder import engine as eng_mod
from boxbuilder.pipeline import install_box
from boxbuilder.spec import BoxSpec

HONOR_SCENARIO = {
    "scenario": {"name": "demo", "version": 1, "mode": "honor", "hosts": ["localhost"]},
    "checks": [],
}
RANKED_SCENARIO = {
    "scenario": {"name": "demo-ranked", "version": 1, "mode": "ranked",
                 "hosts": ["localhost"], "engine_url": "https://engine.example.org"},
    "checks": [],
}


def _compile_result(tmp_path, mode):
    ad = tmp_path / "artifacts"
    ad.mkdir(exist_ok=True)
    for name in ("agent.pyz", "manifest.signed.json", "authoring_public_key.b64",
                 "engine_record.json"):
        (ad / name).write_text("x")
    cr = {
        "mode": mode,
        "scenario_name": "demo-ranked" if mode == "ranked" else "demo",
        "engine_url": "https://engine.example.org" if mode == "ranked" else None,
        "agent_pyz": str(ad / "agent.pyz"),
        "manifest": str(ad / "manifest.signed.json"),
        "authoring_public_key": str(ad / "authoring_public_key.b64"),
        "rubric": None,
        "engine_record": str(ad / "engine_record.json"),
    }
    if mode == "honor":
        (ad / "rubric.json").write_text("x")
        cr["rubric"] = str(ad / "rubric.json")
    return cr


def _spec(mode, provider_name="fake"):
    return BoxSpec(
        scenario_path="/dev/null", nakon_config_path="/dev/null",
        provider={"name": provider_name, "host": "10.0.0.99", "user": "u", "password": "p"},
        base_dir=".",
        scenario=(RANKED_SCENARIO if mode == "ranked" else HONOR_SCENARIO),
        nakon_config={"machines": [{"id": 1, "name": "web01", "configurations": []}]},
    )


def test_install_honor_places_files_and_enables_init(tmp_path, fake_provider_factory,
                                                      fake_provider):
    cr = _compile_result(tmp_path, "honor")
    result = install_box(
        _spec("honor"), artifacts_dir=str(tmp_path), compile_result=cr,
        provider_factory=fake_provider_factory, init_kind="systemd", log=lambda *a: None,
    )
    assert result["ok"] is True
    assert result["mode"] == "honor"
    assert result["init"] == "systemd"
    handle = fake_provider.last_handle
    placed = {os.path.basename(p) for p in result["files"]}
    assert "agent.pyz" in placed
    assert "manifest.signed.json" in placed
    assert "authoring_public_key.b64" in placed
    assert "rubric.json" in placed            # honor-specific
    assert "agent_config.json" in placed
    # All under INSTALL_DIR.
    assert all(p.startswith("/opt/huitzilopochtli/") for p in result["files"])
    # init was actually enabled via the handle.
    assert handle.init_kind == "systemd"
    # mkdir happened.
    assert any("mkdir -p /opt/huitzilopochtli" in c for c in handle.runs)


def test_install_honor_agent_config_shape(tmp_path, fake_provider_factory):
    cr = _compile_result(tmp_path, "honor")
    install_box(_spec("honor"), artifacts_dir=str(tmp_path), compile_result=cr,
                provider_factory=fake_provider_factory, init_kind="none", log=lambda *a: None)
    cfg = json.loads((tmp_path / "artifacts" / "agent_config.json").read_text())
    assert cfg["mode"] == "honor"
    assert cfg["rubric_path"].endswith("/rubric.json")
    assert cfg["identity_path"] is None
    assert cfg["checkin_interval_s"] is None


def test_install_ranked_places_files_without_rubric(tmp_path, fake_provider_factory,
                                                     fake_provider, monkeypatch):
    # Stub the engine client so we don't need a live engine here.
    from boxbuilder import engine as eng_mod
    monkeypatch.setattr(eng_mod, "upload_scenario", lambda *a, **k: {"ok": True})
    monkeypatch.setattr(eng_mod, "mint_enrollment_token",
                        lambda *a, **k: "STUB-TOKEN-123")
    cr = _compile_result(tmp_path, "ranked")
    result = install_box(
        _spec("ranked"), artifacts_dir=str(tmp_path), compile_result=cr,
        provider_factory=fake_provider_factory, init_kind="none",
        admin_token="tok", log=lambda *a: None,
    )
    assert result["ok"] is True
    assert result["mode"] == "ranked"
    placed = {os.path.basename(p) for p in result["files"]}
    assert "rubric.json" not in placed        # stays off-box in ranked
    assert "agent.pyz" in placed
    assert result["ranked"]["scenario_uploaded"] is True
    assert result["ranked"]["enrollment_token"] == "STUB-TOKEN-123"


def test_install_ranked_agent_config_has_token(tmp_path, fake_provider_factory, monkeypatch):
    from boxbuilder import engine as eng_mod
    monkeypatch.setattr(eng_mod, "upload_scenario", lambda *a, **k: {"ok": True})
    monkeypatch.setattr(eng_mod, "mint_enrollment_token", lambda *a, **k: "TOK-XYZ")
    cr = _compile_result(tmp_path, "ranked")
    install_box(_spec("ranked"), artifacts_dir=str(tmp_path), compile_result=cr,
                provider_factory=fake_provider_factory, init_kind="none",
                admin_token="tok", log=lambda *a: None)
    cfg = json.loads((tmp_path / "artifacts" / "agent_config.json").read_text())
    assert cfg["mode"] == "ranked"
    assert cfg["rubric_path"] is None
    assert cfg["identity_path"].endswith("/identity.json")
    assert cfg["checkin_interval_s"] == 60
    assert cfg["enrollment_token"] == "TOK-XYZ"


def test_install_reads_state_when_no_compile_result(tmp_path, fake_provider_factory):
    cr = _compile_result(tmp_path, "honor")
    # Persist it as build-state.json, then call install_box without compile_result.
    (tmp_path / "build-state.json").write_text(json.dumps(cr))
    result = install_box(
        _spec("honor"), artifacts_dir=str(tmp_path),
        provider_factory=fake_provider_factory, init_kind="none", log=lambda *a: None,
    )
    assert result["ok"] is True


def test_install_requires_provider(tmp_path):
    cr = _compile_result(tmp_path, "honor")
    spec = _spec("honor")
    spec.provider = {}  # no provider
    with pytest.raises(ValueError, match="provider"):
        install_box(spec, artifacts_dir=str(tmp_path), compile_result=cr,
                    init_kind="none", log=lambda *a: None)


def test_install_ranked_requires_admin_token(tmp_path, fake_provider_factory, monkeypatch):
    monkeypatch.delenv("HUITZILOPOCHTLI_ADMIN_TOKEN", raising=False)
    # resolve_admin_token returns "" -> upload_scenario raises EngineError.
    cr = _compile_result(tmp_path, "ranked")
    with pytest.raises(eng_mod.EngineError, match="admin token"):
        install_box(_spec("ranked"), artifacts_dir=str(tmp_path), compile_result=cr,
                    provider_factory=fake_provider_factory, init_kind="none",
                    admin_token=None, log=lambda *a: None)
