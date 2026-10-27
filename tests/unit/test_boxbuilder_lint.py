"""boxbuilder lint: the mechanical plant<->check pairing check."""
import json
import os

import pytest
import yaml

from boxbuilder.lint import lint_box
from boxbuilder.spec import load_spec

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BOXES = os.path.join(REPO, "boxes")


def _boxes():
    return sorted(name for name in os.listdir(BOXES)
                  if os.path.isfile(os.path.join(BOXES, name, "box.yaml")))


def _first_box():
    """A real box to exercise lint mechanics against (never named directly)."""
    boxes = _boxes()
    assert boxes
    return os.path.join(BOXES, boxes[0], "box.yaml")


def _box_with_file_path():
    """First box that plants a file by path (the drift case needs one)."""
    for name in _boxes():
        nakon = json.load(open(os.path.join(BOXES, name, "nakon.json"),
                               encoding="utf-8"))
        for item in nakon["machines"][0].get("configurations") or []:
            if isinstance(item, dict) and (item.get("vars") or {}).get("FILE_PATH"):
                return os.path.join(BOXES, name, "box.yaml")
    return None


@pytest.mark.parametrize("box", _boxes())
def test_every_box_lints_clean(box, monkeypatch):
    """No box ships a primary planted path that no check reads."""
    monkeypatch.setenv("HUITZILOPOCHTLI_POOL_TEMPLATE_VM_ID", "1")
    monkeypatch.setenv("HUITZILOPOCHTLI_POOL_TEMPLATE_USER", "u")
    monkeypatch.setenv("HUITZILOPOCHTLI_POOL_TEMPLATE_PASSWORD", "p")
    report = lint_box(load_spec(os.path.join(BOXES, box, "box.yaml")))
    assert report["ok"], report["errors"]


def test_drifted_plant_path_is_an_error(tmp_path, monkeypatch):
    """The failure this lint exists for: a FILE_PATH that no check reads."""
    monkeypatch.setenv("HUITZILOPOCHTLI_POOL_TEMPLATE_VM_ID", "1")
    monkeypatch.setenv("HUITZILOPOCHTLI_POOL_TEMPLATE_USER", "u")
    monkeypatch.setenv("HUITZILOPOCHTLI_POOL_TEMPLATE_PASSWORD", "p")
    drift_box = _box_with_file_path()
    if drift_box is None:
        pytest.skip("no box plants a file by path")
    src = os.path.dirname(drift_box)
    spec = yaml.safe_load(open(os.path.join(src, "box.yaml"), encoding="utf-8"))
    nakon = json.load(open(os.path.join(src, "nakon.json"), encoding="utf-8"))

    # Point one plant at a path the scenario never reads.
    machine = nakon["machines"][0]
    for item in machine["configurations"]:
        if isinstance(item, dict) and item.get("vars", {}).get("FILE_PATH"):
            item["vars"]["FILE_PATH"] = "/opt/cocoa/recipes/moved-recipe.txt"
            break
    else:  # pragma: no cover - the worked example always has one
        pytest.skip("no FILE_PATH configuration in the worked example")

    nakon_path = tmp_path / "nakon.json"
    nakon_path.write_text(json.dumps(nakon))
    spec["scenario"] = os.path.join(src, "scenario.yaml")
    spec["nakon_config"] = str(nakon_path)
    spec_path = tmp_path / "box.yaml"
    spec_path.write_text(yaml.safe_dump(spec))

    loaded = load_spec(str(spec_path))
    # Keep theme assets resolving against the real box directory.
    loaded.base_dir = src
    report = lint_box(loaded)
    assert report["ok"] is False
    assert any("moved-recipe.txt" in message for message in report["errors"])


def test_missing_theme_asset_is_an_error(tmp_path):
    spec = load_spec(_first_box())
    theme = dict(spec.scenario.get("theme") or {})
    theme["wallpaper"] = "assets/does-not-exist.png"
    spec.scenario = dict(spec.scenario, theme=theme)
    report = lint_box(spec)
    assert any("theme.wallpaper" in message for message in report["errors"])


def test_multi_machine_nakon_config_is_rejected(tmp_path):
    spec = load_spec(_first_box())
    src = os.path.dirname(_first_box())
    nakon = json.load(open(os.path.join(src, "nakon.json"), encoding="utf-8"))
    nakon["machines"].append(dict(nakon["machines"][0], name="second"))
    spec.nakon_config = nakon
    report = lint_box(spec)
    assert report["ok"] is False
    assert any("exactly one machine" in message for message in report["errors"])


def test_catalog_check_reports_errors_and_warnings(monkeypatch):
    from boxbuilder import nakon
    monkeypatch.setattr(nakon, "resolve_nakon_dir", lambda *a, **k: "/fake/nakon")
    monkeypatch.setattr(nakon, "catalog_check", lambda *a, **k: {"boxes": [{
        "problems": [
            {"level": "error", "config": "nginx", "message": "missing from catalog"},
            {"level": "warning", "config": "nginx", "message": "implicit service"},
        ]}]})
    report = lint_box(load_spec(_first_box()), catalog=True)
    assert any("missing from catalog" in message for message in report["errors"])
    assert any("implicit service" in message for message in report["warnings"])


def test_catalog_check_unavailable_is_an_error(monkeypatch):
    from boxbuilder import nakon

    def unavailable(*args, **kwargs):
        raise nakon.NakonError("no nakon checkout")

    monkeypatch.setattr(nakon, "resolve_nakon_dir", unavailable)
    report = lint_box(load_spec(_first_box()), catalog=True)
    assert any("catalog check unavailable" in message for message in report["errors"])


def test_catalog_is_opt_in(monkeypatch):
    """An offline lint must not touch nakon at all."""
    from boxbuilder import nakon

    def explode(*args, **kwargs):
        raise AssertionError("offline lint must not invoke nakon")

    monkeypatch.setattr(nakon, "resolve_nakon_dir", explode)
    report = lint_box(load_spec(_first_box()))
    assert report["ok"]
