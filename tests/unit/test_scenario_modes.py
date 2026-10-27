"""The merged scenario model: one authored file, two build targets."""
import os

import pytest
import yaml

from common.scenario_record import (
    LOOPBACK_ENGINE_URL,
    ScenarioModeError,
    base_mode,
    merge_effective,
    resolve_engine_url,
)

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _base(**overrides):
    parsed = {
        "scenario": {"name": "Demo", "version": 1, "mode": "honor",
                     "hosts": ["localhost"]},
        "checks": [{"id": "banner"}],
        "ranked": {
            "engine_url": "https://engine.example.org",
            "checks": [{"id": "ranked_only"}],
            "services": [{"id": "web"}],
            "adversary": {"events": [{"id": "e1"}]},
        },
    }
    parsed.update(overrides)
    return parsed


def test_honor_build_never_sees_ranked_content():
    effective = merge_effective(_base(), "honor")
    assert effective["scenario"]["mode"] == "honor"
    assert "engine_url" not in effective["scenario"]
    assert [c["id"] for c in effective["checks"]] == ["banner"]
    assert effective["services"] == []
    assert effective["adversary"] == {}


def test_ranked_build_appends_ranked_checks_and_blocks():
    effective = merge_effective(_base(), "ranked")
    assert effective["scenario"]["mode"] == "ranked"
    assert effective["scenario"]["engine_url"] == "https://engine.example.org"
    assert [c["id"] for c in effective["checks"]] == ["banner", "ranked_only"]
    assert effective["services"] == [{"id": "web"}]
    assert effective["adversary"] == {"events": [{"id": "e1"}]}


def test_ranked_only_scenario_cannot_build_honor():
    parsed = _base()
    parsed["scenario"]["mode"] = "ranked"
    with pytest.raises(ScenarioModeError, match="no honor variant"):
        merge_effective(parsed, "honor")


def test_honor_scenario_without_ranked_block_cannot_build_ranked():
    parsed = _base()
    parsed.pop("ranked")
    with pytest.raises(ScenarioModeError, match="no ranked variant"):
        merge_effective(parsed, "ranked")


def test_engine_url_resolution_order(monkeypatch):
    parsed = _base()
    assert resolve_engine_url(parsed, "ranked") == "https://engine.example.org"
    monkeypatch.setenv("HUITZILOPOCHTLI_ENGINE_URL", "https://from-env")
    assert resolve_engine_url(parsed, "ranked") == "https://from-env"
    assert resolve_engine_url(parsed, "ranked", "https://from-flag") == "https://from-flag"


def test_missing_engine_url_is_an_error():
    parsed = _base()
    parsed["ranked"].pop("engine_url")
    with pytest.raises(ScenarioModeError, match="engine_url"):
        merge_effective(parsed, "ranked")


def test_pool_placeholders_expand_and_coerce(monkeypatch):
    parsed = _base()
    parsed["ranked"]["pool"] = {
        "template_vm_id": "${HUITZILOPOCHTLI_POOL_TEMPLATE_VM_ID}",
        "template_vm_username": "${HUITZILOPOCHTLI_POOL_TEMPLATE_USER}",
        "template_vm_password": "${HUITZILOPOCHTLI_POOL_TEMPLATE_PASSWORD}",
    }
    monkeypatch.setenv("HUITZILOPOCHTLI_POOL_TEMPLATE_VM_ID", "4242")
    monkeypatch.setenv("HUITZILOPOCHTLI_POOL_TEMPLATE_USER", "u")
    monkeypatch.setenv("HUITZILOPOCHTLI_POOL_TEMPLATE_PASSWORD", "p")
    pool = merge_effective(parsed, "ranked")["pool"]
    assert pool["template_vm_id"] == 4242
    assert isinstance(pool["template_vm_id"], int)


def test_unset_pool_placeholder_names_the_variable(monkeypatch):
    monkeypatch.delenv("HUITZILOPOCHTLI_POOL_TEMPLATE_VM_ID", raising=False)
    parsed = _base()
    parsed["ranked"]["pool"] = {
        "template_vm_id": "${HUITZILOPOCHTLI_POOL_TEMPLATE_VM_ID}",
    }
    with pytest.raises(ScenarioModeError, match="HUITZILOPOCHTLI_POOL_TEMPLATE_VM_ID"):
        merge_effective(parsed, "ranked")


def test_every_box_authors_one_scenario_file():
    """The collapsed layout: no per-mode scenario or spec forks remain."""
    boxes = os.path.join(REPO, "boxes")
    for box in sorted(os.listdir(boxes)):
        box_dir = os.path.join(boxes, box)
        if not os.path.isdir(box_dir):
            continue
        assert not os.path.exists(os.path.join(box_dir, "scenario.ranked.yaml")), box
        assert not os.path.exists(os.path.join(box_dir, "box.ranked.yaml")), box
        assert not os.path.exists(os.path.join(box_dir, "engine_record.json")), box


def test_box_specs_carry_no_deployment_facts():
    boxes = os.path.join(REPO, "boxes")
    for box in sorted(os.listdir(boxes)):
        path = os.path.join(boxes, box, "box.yaml")
        if not os.path.isfile(path):
            continue
        spec = yaml.safe_load(open(path, encoding="utf-8"))
        provider = spec.get("provider") or {}
        assert "host" not in provider, f"{box}: provider.host must not be committed"
        assert "password" not in provider, f"{box}: provider.password must not be committed"
        assert "mode" not in spec, f"{box}: the build target is a CLI argument"
