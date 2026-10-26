import json

import pytest

from authoring.compile import compile_scenario
from common.crypto import signing


SCENARIO = """
scenario:
  name: ServiceTest
  version: 1
  mode: ranked
  engine_url: http://127.0.0.1:8080
  hosts: ["localhost"]
checks:
  - id: banner
    type: file_regex
    category: vuln
    display: Banner
    max_points: 10
    collect: {path: /etc/banner, extract: "(SECURE)"}
    expect: {equals: SECURE, points: 10}
services:
  - id: web
    display: Public web
    type: http_uptime
    collect: {url: "http://127.0.0.1/health"}
    expect: {equals: 200, field: status}
    interval_s: 60
    points_per_interval: 2
  - id: db
    display: Database
    type: tcp_port
    collect: {host: 127.0.0.1, port: 5432}
    expect: {equals: true, field: open}
    interval_s: 30
    points_per_interval: 1
    hysteresis_fail_n: 3
"""


def test_services_compile_into_sla_checks(tmp_path):
    yaml_path = tmp_path / "scenario.yaml"
    yaml_path.write_text(SCENARIO)
    priv, _pub = signing.keypair()
    out = compile_scenario(str(yaml_path), str(tmp_path / "out"), priv)
    manifest = json.load(open(out["manifest"]))
    record = json.load(open(out["engine_record"]))
    assert [s["id"] for s in manifest["services"]] == ["web", "db"]
    assert all("expect" not in s and "points" not in s for s in manifest["services"])
    checks = {c["id"]: c for c in manifest["checks"]}
    assert checks["svc_web"]["is_sla"] is True
    assert checks["svc_db"]["type"] == "tcp_port"
    entries = {e["check_id"]: e for e in record["rubric"]["entries"]}
    assert entries["svc_web"]["points"] == 0
    assert entries["svc_web"]["sla"]["points_per_interval"] == 2
    assert entries["svc_db"]["sla"]["hysteresis_fail_n"] == 3
    assert record["services"][0]["display"] == "Public web"


def test_service_id_collision_is_rejected(tmp_path):
    text = SCENARIO.replace("  - id: banner", "  - id: svc_web\n    type: file_regex\n    category: vuln\n    display: X\n    max_points: 1\n    collect: {path: /x, extract: '(x)'}\n    expect: {equals: x, points: 1}\n  - id: banner", 1)
    yaml_path = tmp_path / "scenario.yaml"
    yaml_path.write_text(text)
    priv, _pub = signing.keypair()
    with pytest.raises(ValueError, match="collides"):
        compile_scenario(str(yaml_path), str(tmp_path / "out"), priv)


def test_pool_block_is_copied_into_the_engine_record(tmp_path):
    yaml_path = tmp_path / "scenario.yaml"
    yaml_path.write_text(SCENARIO + """
pool:
  template_vm_id: 183
  template_vm_access_method: vnc
  template_vm_username: sysadmin
  template_vm_password: asdf
  vm_count: 2
""")
    priv, _pub = signing.keypair()
    out = compile_scenario(str(yaml_path), str(tmp_path / "out"), priv)
    record = json.load(open(out["engine_record"]))
    assert record["pool"] == {
        "template_vm_id": 183, "template_vm_access_method": "vnc",
        "template_vm_username": "sysadmin", "template_vm_password": "asdf",
        "vm_count": 2,
    }


def test_pool_block_on_an_honor_scenario_is_rejected(tmp_path):
    honor = """
scenario:
  name: ServiceTest
  version: 1
  mode: honor
  hosts: ["localhost"]
checks:
  - id: banner
    type: file_regex
    category: vuln
    display: Banner
    max_points: 10
    collect: {path: /etc/banner, extract: "(SECURE)"}
    expect: {equals: SECURE, points: 10}
pool:
  template_vm_id: 183
  template_vm_access_method: vnc
  template_vm_username: sysadmin
  template_vm_password: asdf
"""
    yaml_path = tmp_path / "scenario.yaml"
    yaml_path.write_text(honor)
    priv, _pub = signing.keypair()
    with pytest.raises(ValueError, match="only valid for ranked"):
        compile_scenario(str(yaml_path), str(tmp_path / "out"), priv)
