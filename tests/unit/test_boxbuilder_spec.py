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
        {"id": 1, "name": "web01", "ip": "192.0.2.5", "os": "linux",
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
        f"provider: {{name: ssh, host: 192.0.2.10, user: u, password: p}}\n"
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


def test_theme_absent_is_empty_dict(tmp_path):
    spec = load_spec(str(_write_box(tmp_path)))
    assert spec.theme == {}


def test_theme_reads_through_to_scenario(tmp_path):
    themed = HONOR_SCENARIO + '\ntheme:\n  title: "Op X"\n  accent: "#c8102e"\n'
    spec = load_spec(str(_write_box(tmp_path, themed)))
    assert spec.theme == {"title": "Op X", "accent": "#c8102e"}


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


# --- deployment facts come from the invocation, not the committed spec -----

@pytest.fixture(autouse=True)
def _pool_env(monkeypatch):
    """A ranked compile expands pool placeholders from the environment."""
    monkeypatch.setenv("HUITZILOPOCHTLI_POOL_TEMPLATE_VM_ID", "4242")
    monkeypatch.setenv("HUITZILOPOCHTLI_POOL_TEMPLATE_USER", "template-user")
    monkeypatch.setenv("HUITZILOPOCHTLI_POOL_TEMPLATE_PASSWORD", "template-password")


def _box_with_ranked():
    """First box (alphabetically) that authors a ranked target."""
    import glob
    import yaml
    for path in sorted(glob.glob("boxes/*/box.yaml")):
        scenario = yaml.safe_load(open(
            os.path.join(os.path.dirname(path), "scenario.yaml"), encoding="utf-8"))
        if scenario.get("ranked"):
            return path
    raise AssertionError("no box authors a ranked target")

def _args(**overrides):
    from types import SimpleNamespace
    base = dict(command="plant", provider="ssh", provider_host=None,
                provider_user=None, provider_password=None, provider_port=None)
    base.update(overrides)
    return SimpleNamespace(**base)


def test_provider_flags_override_the_spec():
    from boxbuilder.cli import _apply_provider_overrides
    spec = load_spec(_box_with_ranked())
    spec = _apply_provider_overrides(
        spec, _args(provider_host="192.0.2.55", provider_password="s3cret"))
    assert spec.provider["host"] == "192.0.2.55"
    assert spec.provider["password"] == "s3cret"
    # the spec's own user survives when no flag/env overrides it
    assert spec.provider["user"] == load_spec(_box_with_ranked()).provider["user"]


def test_provider_env_is_the_fallback(monkeypatch):
    from boxbuilder.cli import _apply_provider_overrides
    monkeypatch.setenv("HUITZILOPOCHTLI_PROVIDER_HOST", "198.51.100.9")
    monkeypatch.setenv("HUITZILOPOCHTLI_PROVIDER_USER", "operator")
    monkeypatch.setenv("HUITZILOPOCHTLI_PROVIDER_PASSWORD", "envpass")
    spec = load_spec(_box_with_ranked())
    spec = _apply_provider_overrides(spec, _args())
    assert spec.provider["host"] == "198.51.100.9"
    assert spec.provider["user"] == "operator"
    assert spec.provider["password"] == "envpass"


def test_committed_specs_never_carry_a_host_or_password():
    import glob
    import yaml
    for path in sorted(glob.glob("boxes/*/box.yaml")):
        raw = yaml.safe_load(open(path, encoding="utf-8"))
        provider = raw.get("provider") or {}
        assert "host" not in provider, path
        assert "password" not in provider, path


def test_compile_no_bundle_skips_nakon_and_vulndb(tmp_path, monkeypatch):
    """An install-only ranked template never plants, so it must not need either."""
    from boxbuilder import nakon, pipeline, vulndb

    def explode(*args, **kwargs):
        raise AssertionError("--no-bundle must not touch nakon or vulndb")

    monkeypatch.setattr(nakon, "build_bundle", explode)
    monkeypatch.setattr(vulndb, "ensure_vuln_seeds", explode)

    spec = load_spec(_box_with_ranked())
    result = pipeline.compile_box(spec, str(tmp_path), skip_bundle=True,
                                  log=lambda *a, **k: None)
    assert result["bundle"] is None
    assert result["bundle_path"] is None
    assert result["mode"] == "honor"
    assert os.path.isfile(result["manifest"])


def test_compile_ranked_uses_the_ranked_block(tmp_path):
    from boxbuilder import pipeline
    spec = load_spec(_box_with_ranked(), mode="ranked",
                     engine_url="https://engine.example.org")
    result = pipeline.compile_box(spec, str(tmp_path), skip_bundle=True,
                                  log=lambda *a, **k: None)
    assert result["mode"] == "ranked"
    assert result["engine_url"] == "https://engine.example.org"
    record = json.load(open(result["engine_record"], encoding="utf-8"))
    assert record["mode"] == "ranked"
    assert record["services"]
