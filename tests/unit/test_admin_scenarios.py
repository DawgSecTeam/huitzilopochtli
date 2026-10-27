"""The admin picker lists exactly the ranked scenarios in the box folder.

The engine parses committed ``boxes/<box>/scenario.yaml`` files itself (no
engine_record.json required); engine-DB rows are a serving cache seeded by
``sync_box_scenarios`` and never add picker entries. One current version per
scenario name; a broken box surfaces as a scan error without shadowing the
rest.
"""
import yaml

from common.schema import SCHEMA_VERSION
from engine import scenario as scenario_mod
from engine.store import Store


def _ranked_yaml(name="Demo", version=1, ranked=True):
    parsed = {
        "scenario": {"name": name, "version": version, "mode": "honor",
                     "hosts": ["localhost"]},
        "checks": [{
            "id": "c1", "type": "file_regex", "category": "vuln",
            "display": "C1", "max_points": 5,
            "collect": {"path": "/srv/x", "extract": "X"},
            "expect": {"equals": "X", "points": 5},
        }],
    }
    if ranked:
        parsed["ranked"] = {
            "engine_url": "http://127.0.0.1:8080",
            "services": [],
            "adversary": {},
            "pool": {"template_vm_id": 101,
                     "template_vm_access_method": "ssh",
                     "template_vm_username": "root",
                     "template_vm_password": "pw",
                     "vm_count": 2},
        }
    return yaml.safe_dump(parsed)


def _boxes(tmp_path, monkeypatch):
    boxes = tmp_path / "boxes"
    boxes.mkdir()
    monkeypatch.setattr(scenario_mod, "boxes_dir", lambda: str(boxes))
    return boxes


def _store(tmp_path):
    return Store(str(tmp_path / "engine.db"))


def test_picker_lists_box_folder_scenarios(tmp_path, monkeypatch):
    boxes = _boxes(tmp_path, monkeypatch)
    (boxes / "alpha").mkdir()
    (boxes / "alpha" / "scenario.yaml").write_text(_ranked_yaml("Demo Alpha", 2))
    rows = scenario_mod.list_admin_scenarios()
    assert [(n, v) for n, v, _src in rows] == [("Demo Alpha", 2)]
    assert rows[0][2] == str(boxes / "alpha")


def test_picker_skips_honor_only_boxes(tmp_path, monkeypatch):
    boxes = _boxes(tmp_path, monkeypatch)
    (boxes / "honor").mkdir()
    (boxes / "honor" / "scenario.yaml").write_text(_ranked_yaml("Honor Box", 1,
                                                                ranked=False))
    assert scenario_mod.list_admin_scenarios() == []


def test_picker_is_boxes_only_ignoring_uploaded_records(tmp_path, monkeypatch):
    boxes = _boxes(tmp_path, monkeypatch)
    (boxes / "alpha").mkdir()
    (boxes / "alpha" / "scenario.yaml").write_text(_ranked_yaml("FromFolder", 1))
    store = _store(tmp_path)
    scenario_mod.save_scenario_record(
        store, {"schema_version": SCHEMA_VERSION, "scenario_name": "Uploaded",
                "scenario_version": 1, "entries": []}, {}, [])
    rows = scenario_mod.list_admin_scenarios()
    assert [(n, v) for n, v, _src in rows] == [("FromFolder", 1)]


def test_broken_box_is_reported_and_skipped(tmp_path, monkeypatch):
    boxes = _boxes(tmp_path, monkeypatch)
    (boxes / "alpha").mkdir()
    (boxes / "alpha" / "scenario.yaml").write_text(_ranked_yaml("Good", 1))
    (boxes / "broken").mkdir()
    (boxes / "broken" / "scenario.yaml").write_text("{not: [valid")
    (boxes / "unbuildable").mkdir()
    # A string version fails record validation (must be a non-negative int).
    (boxes / "unbuildable" / "scenario.yaml").write_text(_ranked_yaml("Bad", "2"))
    rows = scenario_mod.list_admin_scenarios()
    assert [(n, v) for n, v, _src in rows] == [("Good", 1)]
    errors = scenario_mod.box_folder_errors()
    assert any("broken" in e for e in errors)
    assert any("unbuildable" in e for e in errors)


def test_same_name_two_versions_higher_wins_with_shadow_error(tmp_path, monkeypatch):
    boxes = _boxes(tmp_path, monkeypatch)
    (boxes / "fork-old").mkdir()
    (boxes / "fork-old" / "scenario.yaml").write_text(_ranked_yaml("Forked", 1))
    (boxes / "fork-new").mkdir()
    (boxes / "fork-new" / "scenario.yaml").write_text(_ranked_yaml("Forked", 2))
    rows = scenario_mod.list_admin_scenarios()
    assert [(n, v) for n, v, _src in rows] == [("Forked", 2)]
    assert any("shadow" in e for e in scenario_mod.box_folder_errors())


def test_same_name_same_version_is_a_collision(tmp_path, monkeypatch):
    boxes = _boxes(tmp_path, monkeypatch)
    (boxes / "copy-a").mkdir()
    (boxes / "copy-a" / "scenario.yaml").write_text(_ranked_yaml("Clash", 1))
    (boxes / "copy-b").mkdir()
    (boxes / "copy-b" / "scenario.yaml").write_text(_ranked_yaml("Clash", 1))
    rows = scenario_mod.list_admin_scenarios()
    assert [(n, v) for n, v, _src in rows] == [("Clash", 1)]
    assert any("rename one of them" in e
               for e in scenario_mod.box_folder_errors())


def test_load_box_scenario_serves_only_the_current_version(tmp_path, monkeypatch):
    boxes = _boxes(tmp_path, monkeypatch)
    (boxes / "alpha").mkdir()
    (boxes / "alpha" / "scenario.yaml").write_text(_ranked_yaml("Demo", 2))
    assert scenario_mod.load_box_scenario("Demo", 2) is not None
    assert scenario_mod.load_box_scenario("Demo", 1) is None
    assert scenario_mod.current_box_scenario("Demo")[0] == 2
    assert scenario_mod.current_box_scenario("Nope") is None


def test_sync_mirrors_folder_and_purges_other_versions(tmp_path, monkeypatch):
    boxes = _boxes(tmp_path, monkeypatch)
    (boxes / "alpha").mkdir()
    (boxes / "alpha" / "scenario.yaml").write_text(_ranked_yaml("Demo", 2))
    store = _store(tmp_path)
    # A stale upload of an older version, plus an orphan scenario.
    scenario_mod.save_scenario_record(
        store, {"schema_version": SCHEMA_VERSION, "scenario_name": "Demo",
                "scenario_version": 1, "entries": []}, {}, [])
    scenario_mod.save_scenario_record(
        store, {"schema_version": SCHEMA_VERSION, "scenario_name": "Orphan",
                "scenario_version": 3, "entries": []}, {}, [])

    errors = scenario_mod.sync_box_scenarios(store)

    assert errors == []
    assert store.get_scenario("Demo", 2) is not None
    assert store.get_scenario("Demo", 1) is None  # stale version purged
    assert store.get_scenario("Orphan", 3) is None  # undeclared name purged


def test_sync_never_purges_when_box_folder_is_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(scenario_mod, "boxes_dir", lambda: "")
    store = _store(tmp_path)
    scenario_mod.save_scenario_record(
        store, {"schema_version": SCHEMA_VERSION, "scenario_name": "Demo",
                "scenario_version": 1, "entries": []}, {}, [])
    assert scenario_mod.sync_box_scenarios(store) == []
    assert store.get_scenario("Demo", 1) is not None


def test_sync_keeps_last_good_record_for_a_broken_box(tmp_path, monkeypatch):
    boxes = _boxes(tmp_path, monkeypatch)
    (boxes / "alpha").mkdir()
    (boxes / "alpha" / "scenario.yaml").write_text(_ranked_yaml("Demo", 1))
    store = _store(tmp_path)
    assert scenario_mod.sync_box_scenarios(store) == []
    # The author breaks the file mid-edit: the name is still declared, so the
    # last good record stays servable and the error surfaces on the picker.
    (boxes / "alpha" / "scenario.yaml").write_text("scenario: {broken")
    errors = scenario_mod.sync_box_scenarios(store)
    assert any("broken" in e for e in errors)
    assert store.get_scenario("Demo", 1) is not None


def test_stale_version_load_names_the_current_version(tmp_path, monkeypatch):
    boxes = _boxes(tmp_path, monkeypatch)
    (boxes / "alpha").mkdir()
    (boxes / "alpha" / "scenario.yaml").write_text(_ranked_yaml("Demo", 2))
    store = _store(tmp_path)
    scenario_mod.save_scenario_record(
        store, {"schema_version": SCHEMA_VERSION, "scenario_name": "Demo",
                "scenario_version": 2, "entries": []}, {}, [])
    try:
        scenario_mod.load_scenario(store, "Demo", 1)
    except scenario_mod.ScenarioNotFound as exc:
        assert "not current" in str(exc) and "v2" in str(exc)
    else:
        raise AssertionError("stale version must not load")
