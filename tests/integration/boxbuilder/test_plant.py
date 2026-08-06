"""Integration tests for boxbuilder.pipeline.plant_box (step 2).

Drives plant_box end-to-end with a FakeProvider and a fake `nakon deploy`,
asserting: address reconciliation (vulns from agent, addr from provider),
the derived deploy config is written, and the deploy result is passed through.
No real VM, no real paramiko, no real vulndb.
"""
import json

import pytest

from tests.integration.boxbuilder._fakes import install_fake_nakon
from boxbuilder.pipeline import plant_box
from boxbuilder.spec import BoxSpec

SCENARIO = {
    "scenario": {"name": "Demo", "version": 1, "mode": "honor", "hosts": ["localhost"]},
    "checks": [],
}
NAKON_CONFIG = {
    "machines": [
        {"id": 1, "name": "web01", "ip": "10.0.0.5", "os": "linux",
         "user": "agentuser", "password": "agentpass",
         "configurations": ["nginx", "ssh-root-login"]}
    ]
}


def _spec(provider_cfg):
    return BoxSpec(
        scenario_path="/dev/null", nakon_config_path="/dev/null",
        provider=provider_cfg, base_dir=".",
        scenario=SCENARIO, nakon_config=NAKON_CONFIG,
    )


def test_plant_uses_provider_address(tmp_path, monkeypatch, fake_provider_factory):
    # The provider will report this address; it must override the agent config's.
    cfg = {"name": "fake", "host": "192.168.50.10", "user": "provuser",
           "password": "provpass", "port": 2222}
    deploy_json = {"bundle_id": "bid", "machines": [], "failures": 0, "ok": True, "log_dir": None}
    nakon_dir = install_fake_nakon(
        tmp_path, monkeypatch, deploy_json=deploy_json
    )
    # Pre-create a bundle dir so the bundle_path check passes.
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    result = plant_box(
        _spec(cfg), artifacts_dir=str(tmp_path), bundle_path=str(bundle),
        nakon_dir=nakon_dir, provider_factory=fake_provider_factory, log=lambda *a: None,
    )
    assert result["ok"] is True
    assert result["machine"]["addr"] == "192.168.50.10"
    assert result["machine"]["user"] == "provuser"
    assert result["machine"]["port"] == 2222

    # The derived deploy config captured the provider's address + agent's vulns.
    derived = json.loads((tmp_path / "nakon-deploy-config.json").read_text())
    m = derived["machines"][0]
    assert m["ip"] == "192.168.50.10"
    assert m["user"] == "provuser"
    assert m["password"] == "provpass"
    assert m["port"] == 2222
    assert m["configurations"] == ["nginx", "ssh-root-login"]
    assert m["name"] == "web01"


def test_plant_fails_without_provider(tmp_path):
    with pytest.raises(ValueError, match="provider"):
        plant_box(_spec({}), artifacts_dir=str(tmp_path), bundle_path=str(tmp_path),
                  log=lambda *a: None)


def test_plant_fails_without_bundle(tmp_path):
    # No bundle passed and no build-state.json -> clear error.
    with pytest.raises(ValueError, match="no bundle"):
        plant_box(_spec({"name": "fake", "host": "h", "user": "u", "password": "p"}),
                  artifacts_dir=str(tmp_path), provider_factory=lambda n, c: (None, None),
                  log=lambda *a: None)


def test_plant_reads_bundle_from_state(tmp_path, monkeypatch, fake_provider_factory):
    """If bundle_path is omitted, plant reads it from build-state.json."""
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (tmp_path / "build-state.json").write_text(json.dumps({"bundle_path": str(bundle)}))
    deploy_json = {"bundle_id": "b", "machines": [], "failures": 0, "ok": True, "log_dir": None}
    nakon_dir = install_fake_nakon(
        tmp_path, monkeypatch, deploy_json=deploy_json
    )
    result = plant_box(
        _spec({"name": "fake", "host": "h", "user": "u", "password": "p"}),
        artifacts_dir=str(tmp_path), nakon_dir=nakon_dir,
        provider_factory=fake_provider_factory, log=lambda *a: None,
    )
    assert result["ok"] is True


def test_plant_reports_failures(tmp_path, monkeypatch, fake_provider_factory):
    """When nakon deploy reports failures, result.ok is False and exit reflects it."""
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    deploy_json = {"bundle_id": "b", "machines": [], "failures": 2, "ok": False, "log_dir": None}
    nakon_dir = install_fake_nakon(
        tmp_path, monkeypatch, deploy_json=deploy_json
    )
    result = plant_box(
        _spec({"name": "fake", "host": "h", "user": "u", "password": "p"}),
        artifacts_dir=str(tmp_path), bundle_path=str(bundle), nakon_dir=nakon_dir,
        provider_factory=fake_provider_factory, log=lambda *a: None,
    )
    assert result["ok"] is False
    assert result["deploy"]["failures"] == 2
