"""Per-box pool deployment map for the engine's box-folder source."""
import os

import pytest
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


def test_scan_reports_an_unset_placeholder_as_an_unusable_scenario(
        tmp_path, monkeypatch):
    """An unresolvable pool marks the scenario unusable -- it does not delete it.

    The scan used to drop the box from the folder pass entirely, which turned
    the admin picker into a 400 and made the API claim the box folder held no
    such scenario. Now the scenario is listed, its pool is None, and the
    reason rides on it so the page can say what to fix.
    """
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
    assert errors == (), errors
    assert found and "Pool Box" in found
    version, _path, record = found["Pool Box"]
    assert version == 1
    assert record[3] is None  # pool unusable: nothing to clone from
    problem = scenario.pool_problem("Pool Box")
    assert problem and "unset environment variable" in problem


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


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file modes")
def test_unreadable_pool_map_says_who_must_read_it(tmp_path, monkeypatch):
    """A root-owned 0600 pools file must name the readable-by problem.

    The engine runs as an unprivileged user; when the file exists but that
    user cannot read it, the error has to say so -- a bare errno left
    operators staring at a perfectly valid file.
    """
    root = tmp_path / "boxes"
    root.mkdir()
    _box(root)
    pools = _pools(tmp_path, {})
    os.chmod(pools, 0o000)
    monkeypatch.setenv("HUITZILOPOCHTLI_POOLS_FILE", str(pools))
    monkeypatch.setattr(scenario, "boxes_dir", lambda: str(root))
    _reset_scan()
    try:
        found, errors = scenario._scan_box_folder()
    finally:
        os.chmod(pools, 0o600)
    assert found is None and errors
    assert "readable by" in errors[0], errors


def test_stamp_moves_on_mode_and_owner_changes(tmp_path, monkeypatch):
    """chmod/chown move neither mtime nor size -- the stamp must see them.

    An unreadable-chmod of the pools file mid-run is the real deployment
    failure; the scan cache only revalidates when source_stamp() moves, so
    mode and owner have to ride the key.
    """
    pools = _pools(tmp_path, {"Pool Box": {
        "template_vm_id": 4242, "template_vm_access_method": "ssh",
        "template_vm_username": "u", "template_vm_password": "p",
        "vm_count": 1}})
    monkeypatch.setenv("HUITZILOPOCHTLI_POOLS_FILE", str(pools))
    before = pool_config.source_stamp()
    os.chmod(pools, 0o600)
    assert pool_config.source_stamp() != before
    os.chmod(pools, 0o000)
    assert pool_config.source_stamp() != before


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file modes")
def test_mid_run_unreadable_chmod_is_caught(tmp_path, monkeypatch):
    """A good scan followed by a bad chmod must surface on the next scan."""
    root = tmp_path / "boxes"
    root.mkdir()
    _box(root)
    pools = _pools(tmp_path, {"Pool Box": {
        "template_vm_id": 4242, "template_vm_access_method": "ssh",
        "template_vm_username": "u", "template_vm_password": "p",
        "vm_count": 1}})
    monkeypatch.setenv("HUITZILOPOCHTLI_POOLS_FILE", str(pools))
    monkeypatch.setattr(scenario, "boxes_dir", lambda: str(root))
    _reset_scan()
    found, errors = scenario._scan_box_folder()
    assert errors == () and found
    os.chmod(pools, 0o000)
    try:
        found2, errors2 = scenario._scan_box_folder()
    finally:
        os.chmod(pools, 0o600)
    assert found2 is None and errors2
    assert any("readable by" in e for e in errors2), errors2
