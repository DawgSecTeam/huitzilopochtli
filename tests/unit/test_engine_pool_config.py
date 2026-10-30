"""Per-box pool deployment map for the engine's box-folder source."""
import os

import yaml

from engine import pool_config, scenario

BOX = """\
scenario:
  name: "Pool Box"
  version: 1
  mode: honor
  hosts: ["localhost"]
  engine_url: "http://127.0.0.1:8080"
checks: []
ranked:
  engine_url: "http://127.0.0.1:8080"
  services: []
  pool:
    template_vm_id: "${HUITZILOPOCHTLI_POOL_TEMPLATE_VM_ID}"
    template_vm_access_method: ssh
    template_vm_username: "${HUITZILOPOCHTLI_POOL_TEMPLATE_USER}"
    template_vm_password: "${HUITZILOPOCHTLI_POOL_TEMPLATE_PASSWORD}"
    vm_count: 1
"""


def _box(root, name="pool-box", text=BOX):
    directory = root / name
    directory.mkdir(parents=True)
    (directory / "scenario.yaml").write_text(text, encoding="utf-8")
    return directory


def _pools(tmp_path, scenarios):
    path = tmp_path / "pools.yaml"
    path.write_text(yaml.safe_dump({"scenarios": scenarios}), encoding="utf-8")
    return path


def _reset_scan():
    scenario._SCAN_CACHE["key"] = None
    scenario._SCAN_CACHE["result"] = (None, ())


def test_apply_overrides_replaces_only_the_pool():
    parsed = {
        "scenario": {"name": "Pool Box"},
        "ranked": {"engine_url": "http://x", "services": [],
                   "pool": {"template_vm_id": "${VM}"}},
    }
    out = pool_config.apply_overrides(parsed, {
        "Pool Box": {"template_vm_id": 7, "template_vm_access_method": "ssh",
                     "template_vm_username": "u",
                     "template_vm_password": "p"},
    })
    assert out["ranked"]["pool"]["template_vm_id"] == 7
    assert out["ranked"]["engine_url"] == "http://x"
    assert parsed["ranked"]["pool"]["template_vm_id"] == "${VM}"


def test_scan_uses_the_per_box_pool_map(tmp_path, monkeypatch):
    root = tmp_path / "boxes"
    root.mkdir()
    _box(root)
    pools = _pools(tmp_path, {"Pool Box": {
        "template_vm_id": 4242, "template_vm_access_method": "ssh",
        "template_vm_username": "template-user",
        "template_vm_password": "template-password", "vm_count": 1}})
    monkeypatch.setenv("HUITZILOPOCHTLI_POOLS_FILE", str(pools))
    monkeypatch.setattr(scenario, "boxes_dir", lambda: str(root))
    _reset_scan()
    found, errors = scenario._scan_box_folder()
    assert errors == ()
    version, _path, record = found["Pool Box"]
    assert version == 1
    assert record[3]["template_vm_id"] == 4242


def test_scan_reports_an_unset_placeholder_without_a_map_entry(
        tmp_path, monkeypatch):
    root = tmp_path / "boxes"
    root.mkdir()
    _box(root)
    pools = _pools(tmp_path, {})
    monkeypatch.setenv("HUITZILOPOCHTLI_POOLS_FILE", str(pools))
    for name in ("HUITZILOPOCHTLI_POOL_TEMPLATE_VM_ID",
                 "HUITZILOPOCHTLI_POOL_TEMPLATE_USER",
                 "HUITZILOPOCHTLI_POOL_TEMPLATE_PASSWORD"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(scenario, "boxes_dir", lambda: str(root))
    _reset_scan()
    found, errors = scenario._scan_box_folder()
    assert found is None or found == {}
    assert any("unset environment variable" in e for e in errors), errors


def test_malformed_pool_map_is_a_scan_error(tmp_path, monkeypatch):
    root = tmp_path / "boxes"
    root.mkdir()
    _box(root)
    bad = tmp_path / "pools.yaml"
    bad.write_text("scenarios: [not, a, map]\n", encoding="utf-8")
    monkeypatch.setenv("HUITZILOPOCHTLI_POOLS_FILE", str(bad))
    monkeypatch.setattr(scenario, "boxes_dir", lambda: str(root))
    _reset_scan()
    found, errors = scenario._scan_box_folder()
    assert found is None and errors and "scenarios" in errors[0]
