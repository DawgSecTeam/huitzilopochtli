"""Integration tests for boxbuilder.pipeline.package_box (step 4) and
build_all (the resumable full pipeline).

package_box: exercises the provider's export() and asserts the manual-export
path (SshProvider's behavior) is surfaced, not treated as failure.

build_all: drives the full compile->plant->install->package chain with a
FakeProvider + a fake nakon, for honor mode (no engine needed). Also covers
resumability: resume from a later step against build-state.json.
"""
import json
import os

import pytest

from tests.integration.boxbuilder._fakes import FakeProvider, install_fake_nakon
from boxbuilder.pipeline import build_all, package_box
from boxbuilder.spec import BoxSpec

HONOR_SCENARIO_YAML = """\
scenario:
  name: "Linux Fundamentals"
  version: 1
  mode: honor
  hosts: ["localhost"]
checks:
  - id: ssh_no_root
    type: file_regex
    category: vuln
    display: "Disabled SSH root login"
    max_points: 5
    collect:
      path: /etc/ssh/sshd_config
      extract: '^\\s*PermitRootLogin\\s+(\\S+)'
    expect:
      equals: "no"
      points: 5
"""
NAKON_CONFIG = {
    "machines": [
        {"id": 1, "name": "web01", "ip": "10.0.0.5", "os": "linux",
         "user": "ubuntu", "password": "ubuntu",
         "configurations": ["nginx", "ssh-root-login"]}
    ]
}

SCENARIO = {
    "scenario": {"name": "Demo", "version": 1, "mode": "honor", "hosts": ["localhost"]},
    "checks": [],
}


def _spec(provider_name="fake"):
    return BoxSpec(
        scenario_path="/dev/null", nakon_config_path="/dev/null",
        provider={"name": provider_name, "host": "10.0.0.99", "user": "u", "password": "p"},
        base_dir=".", scenario=SCENARIO, nakon_config=NAKON_CONFIG,
    )


# --- package_box ----------------------------------------------------------
def test_package_manual_export_is_ok(tmp_path, fake_provider_factory, fake_provider):
    """The fake provider's FakeHandle.export returns mode=wrote. But the SSH
    provider returns mode=manual (can't self-export). Cover the manual path by
    patching the handle's export."""
    # Force manual export by overriding the handle's export after start.
    from boxbuilder.providers.base import ExportResult

    def _factory(name, cfg):
        prov = FakeProvider()
        handle = prov.start(cfg)

        def _manual(out_path, fmt="ova"):
            handle.exported = (out_path, fmt)
            return ExportResult(mode="manual", instructions="snap it from the hypervisor")

        handle.export = _manual
        return prov, handle

    result = package_box(_spec(), artifacts_dir=str(tmp_path), image_out="/tmp/x.ova",
                         fmt="ova", provider_factory=_factory, log=lambda *a: None)
    assert result["ok"] is True  # manual is not failure
    assert result["image"]["mode"] == "manual"
    assert result["image"]["path"] is None
    assert "hypervisor" in result["image"]["instructions"]


def test_package_wrote_export(tmp_path, fake_provider_factory):
    result = package_box(_spec(), artifacts_dir=str(tmp_path), image_out="/tmp/y.ova",
                         provider_factory=fake_provider_factory, log=lambda *a: None)
    assert result["ok"] is True
    assert result["image"]["mode"] == "wrote"
    assert result["image"]["path"] == "/tmp/y.ova"
    assert result["image"]["format"] == "ova"


def test_package_requires_provider(tmp_path):
    spec = _spec()
    spec.provider = {}
    with pytest.raises(ValueError, match="provider"):
        package_box(spec, artifacts_dir=str(tmp_path), image_out="/tmp/z.ova",
                    log=lambda *a: None)


# --- build_all: full pipeline (honor) -------------------------------------
def _write_real_scenario(tmp_path):
    """Write a real scenario YAML so compile_scenario actually succeeds, and a
    real nakon config. Returns (scenario_path, nakon_config_path)."""
    sc = tmp_path / "scenario.yaml"
    sc.write_text(HONOR_SCENARIO_YAML)
    nc = tmp_path / "nakon-config.json"
    nc.write_text(json.dumps(NAKON_CONFIG))
    return str(sc), str(nc)


def _real_spec(tmp_path):
    sc, nc = _write_real_scenario(tmp_path)
    return BoxSpec(
        scenario_path=sc, nakon_config_path=nc,
        provider={"name": "fake", "host": "10.0.0.99", "user": "u", "password": "p"},
        base_dir=str(tmp_path),
        scenario=None, nakon_config=None,  # load via the real files
    )


def test_build_all_full_honor(tmp_path, monkeypatch, fake_provider_factory):
    # Real scenario file -> need to load via load_spec semantics. Build the spec
    # by loading the scenario + nakon config the same way load_spec does.
    import yaml
    sc, nc = _write_real_scenario(tmp_path)
    with open(sc) as f:
        scenario = yaml.safe_load(f)
    with open(nc) as f:
        nakon_config = json.load(f)
    spec = BoxSpec(
        scenario_path=sc, nakon_config_path=nc,
        provider={"name": "fake", "host": "10.0.0.99", "user": "u", "password": "p"},
        base_dir=str(tmp_path), scenario=scenario, nakon_config=nakon_config,
    )
    # Fake nakon for build + deploy.
    nakon_dir = install_fake_nakon(
        tmp_path, monkeypatch,
        build_json={"bundle_id": "bid", "path": "bundles/bid",
                    "cached": False, "plans": 1, "machines": 1},
        deploy_json={"bundle_id": "bid", "machines": [], "failures": 0, "ok": True, "log_dir": None},
    )

    result = build_all(
        spec, artifacts_dir=str(tmp_path / "artifacts"),
        image_out=str(tmp_path / "box.ova"), fmt="ova",
        nakon_dir=nakon_dir, provider_factory=fake_provider_factory,
        init_kind="none", log=lambda *a: None,
    )
    assert result["ok"] is True
    assert "compile" in result and result["compile"]["mode"] == "honor"
    assert result["plant"]["ok"] is True
    assert result["install"]["ok"] is True
    assert result["package"]["image"]["mode"] == "wrote"
    # build-state.json was written.
    assert (tmp_path / "artifacts" / "build-state.json").exists()
    # agent.pyz was actually built.
    assert (tmp_path / "artifacts" / "agent.pyz").exists()


def test_build_all_resume_from_install(tmp_path, fake_provider_factory):
    """Resuming from 'install' loads compile state from build-state.json and
    skips compile+plant."""
    # Pre-seed a minimal build-state.json + the artifact files install needs.
    ad = tmp_path / "artifacts"
    ad.mkdir()
    for name in ("agent.pyz", "manifest.signed.json", "authoring_public_key.b64", "rubric.json",
                 "engine_record.json"):
        (ad / name).write_text("x")
    state = {
        "mode": "honor", "scenario_name": "Demo", "engine_url": None,
        "agent_pyz": str(ad / "agent.pyz"),
        "manifest": str(ad / "manifest.signed.json"),
        "authoring_public_key": str(ad / "authoring_public_key.b64"),
        "rubric": str(ad / "rubric.json"),
        "engine_record": str(ad / "engine_record.json"),
        "bundle": {"bundle_id": "bid", "path": str(ad / "bundle"), "cached": False,
                   "plans": 1, "machines": 1},
        "bundle_path": str(ad / "bundle"),
    }
    (ad / "build-state.json").write_text(json.dumps(state))

    result = build_all(
        _spec(), artifacts_dir=str(ad), from_step="install",
        image_out=str(tmp_path / "box.ova"),
        provider_factory=fake_provider_factory, init_kind="none", log=lambda *a: None,
    )
    assert result["ok"] is True
    # compile/plant were skipped (only their state loaded).
    assert "compile" in result  # loaded state
    assert "plant" not in result  # not run
    assert result["install"]["ok"] is True
    assert result["package"]["image"]["mode"] == "wrote"


def test_build_all_resume_without_state_fails(tmp_path, fake_provider_factory):
    with pytest.raises(ValueError, match="build-state.json"):
        build_all(_spec(), artifacts_dir=str(tmp_path / "nope"), from_step="install",
                  image_out=str(tmp_path / "x.ova"),
                  provider_factory=fake_provider_factory, log=lambda *a: None)


def test_build_all_package_requires_image_out(tmp_path, monkeypatch, fake_provider_factory):
    import yaml
    sc, nc = _write_real_scenario(tmp_path)
    with open(sc) as f:
        scenario = yaml.safe_load(f)
    with open(nc) as f:
        nakon_config = json.load(f)
    spec = BoxSpec(scenario_path=sc, nakon_config_path=nc,
                   provider={"name": "fake", "host": "h", "user": "u", "password": "p"},
                   base_dir=str(tmp_path), scenario=scenario, nakon_config=nakon_config)
    nakon_dir = install_fake_nakon(
        tmp_path, monkeypatch,
        build_json={"bundle_id": "b", "path": "bundles/b", "cached": False,
                    "plans": 1, "machines": 1},
        deploy_json={"ok": True, "failures": 0, "machines": [], "log_dir": None, "bundle_id": "b"},
    )
    with pytest.raises(ValueError, match="image-out"):
        build_all(spec, artifacts_dir=str(tmp_path / "artifacts"),
                  nakon_dir=nakon_dir, provider_factory=fake_provider_factory,
                  init_kind="none", log=lambda *a: None)
