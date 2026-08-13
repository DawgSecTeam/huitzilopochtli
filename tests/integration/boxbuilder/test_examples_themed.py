"""Smoke + compile_box coverage for the themed worked example,
boxbuilder/examples/linux-fundamentals-themed.{scenario,box}.yaml.

Mirrors test_examples.py's structure for the plain example, plus the piece specific to
theming: compile_box must resolve theme assets and append the right vulndb catalog
configuration entries (name + vars) to every machine's `configurations` list in the
nakon-config.json it writes -- nakon's config.json shape is otherwise completely
unchanged, and the compiled manifest still carries the small cosmetic subset
(title/organization/accent/logo_b64) -- never wallpaper/readme/motd, which stay
vulndb-only (see boxbuilder/theme.py, boxbuilder/vulndb.py).

vulndb.ensure_configuration/ensure_attachment are monkeypatched here (no real vulndb-ui
needed in CI) -- see test_boxbuilder_vulndb.py for real-HTTP-shape coverage, and this
was additionally verified live against a real vulndb-ui + real nakon during development.
"""
import json
import os

import pytest
import yaml

from authoring.compile import compile_scenario
from authoring.validate import validate_scenario_yaml
from boxbuilder import theme as theme_mod
from boxbuilder.pipeline import compile_box
from boxbuilder.spec import load_spec
from common.crypto import signing
from tests.integration.boxbuilder._fakes import install_fake_nakon

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
EXAMPLES = os.path.join(REPO_ROOT, "boxbuilder", "examples")
THEMED_SCENARIO = os.path.join(EXAMPLES, "linux-fundamentals-themed.scenario.yaml")
THEMED_BOX = os.path.join(EXAMPLES, "linux-fundamentals-themed.box.yaml")


def test_themed_example_scenario_validates():
    with open(THEMED_SCENARIO) as f:
        parsed = yaml.safe_load(f)
    errors = validate_scenario_yaml(parsed, THEMED_SCENARIO)
    assert errors == [], f"themed example scenario has validation errors: {errors}"


def test_themed_example_scenario_compiles_with_theme_in_manifest(tmp_path):
    priv, _ = signing.keypair()
    outputs = compile_scenario(THEMED_SCENARIO, str(tmp_path), priv)
    manifest = json.load(open(outputs["manifest"]))
    theme = manifest["theme"]
    assert theme["title"] == "Operation Featherstorm"
    assert theme["organization"] == "DawgSec"
    assert theme["accent"] == "#c8102e"
    assert theme["logo_b64"], "logo should be embedded as base64"
    # Box-decoration fields must NOT leak into the signed manifest.
    for leaked in ("wallpaper", "readme", "motd", "forensics_questions", "desktop_shortcuts"):
        assert leaked not in theme


def test_themed_example_box_spec_resolves():
    spec = load_spec(THEMED_BOX)
    assert spec.mode == "honor"
    assert spec.theme["title"] == "Operation Featherstorm"


@pytest.fixture
def fake_vulndb(monkeypatch):
    """Records ensure_configuration/ensure_attachment calls and returns stable fake
    filenames -- see test_boxbuilder_theme.py for the identical pattern."""
    calls = []

    def _ensure_configuration(url, definition, timeout=30):
        calls.append(("ensure_configuration", definition["name"]))
        return {"id": 1, "name": definition["name"], "attachments": []}

    def _ensure_attachment(url, configuration, local_path, timeout=60):
        calls.append(("ensure_attachment", configuration["name"], local_path))
        return f"fakehash-{os.path.basename(local_path)}"

    monkeypatch.setattr(theme_mod.vulndb, "ensure_configuration", _ensure_configuration)
    monkeypatch.setattr(theme_mod.vulndb, "ensure_attachment", _ensure_attachment)
    return calls


def test_compile_box_appends_theme_configurations_to_every_machine(
    tmp_path, monkeypatch, fake_vulndb,
):
    spec = load_spec(THEMED_BOX)
    nakon_dir = install_fake_nakon(
        tmp_path, monkeypatch,
        build_json={"bundle_id": "bid", "path": "bundles/bid",
                    "cached": False, "plans": 1, "machines": 1},
    )
    artifacts_dir = str(tmp_path / "artifacts")
    compile_box(spec, artifacts_dir, nakon_dir=nakon_dir, log=lambda *a: None)

    nakon_cfg = json.load(open(os.path.join(artifacts_dir, "nakon-config.json")))
    # nakon's config.json shape is completely unchanged -- no "theme" key anywhere.
    assert "theme" not in nakon_cfg

    original = spec.nakon_config["machines"][0]["configurations"]
    got = nakon_cfg["machines"][0]["configurations"]

    # Original vuln configurations are untouched, theme entries appended after them.
    assert got[:len(original)] == original
    appended = got[len(original):]
    names = [e["name"] if isinstance(e, dict) else e for e in appended]
    assert names == ["theme-wallpaper", "theme-motd", "theme-readme", "theme-shortcuts"]

    by_name = {e["name"]: e for e in appended}
    assert by_name["theme-wallpaper"]["vars"]["WALLPAPER_FILENAME"] == "fakehash-wallpaper.png"
    assert "Authorized use only" in by_name["theme-motd"]["vars"]["MOTD_TEXT"]
    assert by_name["theme-readme"]["vars"]["README_FILENAME"] == "fakehash-README.md"
    assert "Q1:" in by_name["theme-readme"]["vars"]["FORENSICS_TEXT"]
    assert by_name["theme-shortcuts"]["vars"]["SHORTCUT_NAME"] == "Scoring Report"

    # wallpaper/readme were uploaded from real, existing, absolute example asset paths.
    upload_paths = [c[2] for c in fake_vulndb if c[0] == "ensure_attachment"]
    assert any(p.endswith(os.path.join("assets", "wallpaper.png")) for p in upload_paths)
    assert any(p.endswith(os.path.join("assets", "README.md")) for p in upload_paths)
    assert all(os.path.isabs(p) and os.path.isfile(p) for p in upload_paths)


def test_compile_box_without_theme_writes_nakon_config_unchanged(tmp_path, monkeypatch):
    """Regression guard: a spec with no theme block must produce a byte-identical
    nakon-config.json to what compile_box wrote before theming existed."""
    path = os.path.join(EXAMPLES, "linux-fundamentals.box.yaml")
    spec = load_spec(path)
    assert spec.theme == {}

    nakon_dir = install_fake_nakon(
        tmp_path, monkeypatch,
        build_json={"bundle_id": "bid", "path": "bundles/bid",
                    "cached": False, "plans": 1, "machines": 1},
    )
    artifacts_dir = str(tmp_path / "artifacts")
    compile_box(spec, artifacts_dir, nakon_dir=nakon_dir, log=lambda *a: None)

    nakon_cfg = json.load(open(os.path.join(artifacts_dir, "nakon-config.json")))
    assert "theme" not in nakon_cfg
    assert nakon_cfg == spec.nakon_config
