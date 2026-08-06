"""Unit tests for boxbuilder.spec.load_spec / BoxSpec."""
import json
import os

import pytest

from boxbuilder.spec import BoxSpec, load_spec

HONOR_SCENARIO = """\
scenario:
  name: "Demo"
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

RANKED_SCENARIO = HONOR_SCENARIO.replace('mode: honor', 'mode: ranked').replace(
    '  hosts: ["localhost"]', '  hosts: ["localhost"]\n  engine_url: "https://engine.example.org"'
)

NAKON_CONFIG = {
    "machines": [
        {"id": 1, "name": "web01", "ip": "10.0.0.5", "os": "linux",
         "user": "ubuntu", "password": "ubuntu",
         "configurations": ["nginx", "ssh-root-login"]}
    ]
}


def _write_box(tmp_path, scenario_text=HONOR_SCENARIO):
    sc = tmp_path / "scenario.yaml"
    sc.write_text(scenario_text)
    nc = tmp_path / "nakon-config.json"
    nc.write_text(json.dumps(NAKON_CONFIG))
    spec = tmp_path / "box.yaml"
    spec.write_text(
        f"scenario: {sc.name}\nnakon_config: {nc.name}\n"
        f"provider: {{name: ssh, host: 192.168.1.10, user: u, password: p}}\n"
    )
    return spec


def test_load_spec_honor(tmp_path):
    spec = load_spec(str(_write_box(tmp_path)))
    assert spec.mode == "honor"
    assert spec.engine_url is None
    assert spec.nakon_machines()[0]["name"] == "web01"
    assert spec.provider["name"] == "ssh"


def test_load_spec_ranked(tmp_path):
    spec = load_spec(str(_write_box(tmp_path, RANKED_SCENARIO)))
    assert spec.mode == "ranked"
    assert spec.engine_url == "https://engine.example.org"


def test_mode_is_read_from_scenario_not_spec(tmp_path):
    # If the spec tried to override mode it couldn't; mode lives in the scenario.
    spec = load_spec(str(_write_box(tmp_path)))
    assert spec.scenario["scenario"]["mode"] == spec.mode


def test_relative_paths_resolve_against_spec_dir(tmp_path):
    sub = tmp_path / "deep"
    sub.mkdir()
    sc = sub / "scenario.yaml"
    sc.write_text(HONOR_SCENARIO)
    nc = sub / "nakon-config.json"
    nc.write_text(json.dumps(NAKON_CONFIG))
    spec = tmp_path / "box.yaml"  # spec in parent dir, refs in subdir
    spec.write_text("scenario: deep/scenario.yaml\nnakon_config: deep/nakon-config.json\n")
    loaded = load_spec(str(spec))
    assert os.path.isabs(loaded.scenario_path)
    assert loaded.scenario_path.endswith("deep/scenario.yaml")


def test_missing_scenario_key(tmp_path):
    spec = tmp_path / "box.yaml"
    spec.write_text("nakon_config: x.json\n")
    with pytest.raises(ValueError, match="scenario"):
        load_spec(str(spec))


def test_missing_nakon_config_key(tmp_path):
    spec = tmp_path / "box.yaml"
    spec.write_text("scenario: x.yaml\n")
    with pytest.raises(ValueError, match="nakon_config"):
        load_spec(str(spec))


def test_nonexistent_scenario_path(tmp_path):
    spec = tmp_path / "box.yaml"
    spec.write_text("scenario: nope.yaml\nnakon_config: also_nope.json\n")
    with pytest.raises(ValueError, match="does not exist"):
        load_spec(str(spec))


def test_bad_mode_rejected(tmp_path):
    bad = HONOR_SCENARIO.replace("mode: honor", "mode: bogus")
    spec = _write_box(tmp_path, bad)
    with pytest.raises(ValueError, match="mode"):
        load_spec(str(spec))


def test_ranked_without_engine_url_rejected(tmp_path):
    bad = HONOR_SCENARIO.replace("mode: honor", "mode: ranked")  # no engine_url
    spec = _write_box(tmp_path, bad)
    with pytest.raises(ValueError, match="engine_url"):
        load_spec(str(spec))


def test_nakon_config_without_machines_rejected(tmp_path):
    sc = tmp_path / "scenario.yaml"
    sc.write_text(HONOR_SCENARIO)
    nc = tmp_path / "nakon-config.json"
    nc.write_text(json.dumps({"not_machines": []}))
    spec = tmp_path / "box.yaml"
    spec.write_text(f"scenario: {sc.name}\nnakon_config: {nc.name}\n")
    with pytest.raises(ValueError, match="machines"):
        load_spec(str(spec))


def test_top_level_must_be_mapping(tmp_path):
    spec = tmp_path / "box.yaml"
    spec.write_text("- a list\n- not a mapping\n")
    with pytest.raises(ValueError, match="mapping"):
        load_spec(str(spec))
