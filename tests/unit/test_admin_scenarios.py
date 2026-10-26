"""The admin picker must offer uploaded engine records, not just a box folder.

The deployed engine ships without the repo's `boxes/` directory, so a picker
that only scanned that folder showed "No ranked scenarios found" even though
the engine held valid uploaded records.
"""
import json

from common.schema import SCHEMA_VERSION
from engine import scenario as scenario_mod
from engine.store import Store


def _rubric(name="Uploaded"):
    return {"schema_version": SCHEMA_VERSION, "scenario_name": name,
            "scenario_version": 1, "entries": []}


def _store(tmp_path):
    return Store(str(tmp_path / "engine.db"))


def test_picker_offers_uploads_when_no_box_folder_exists(tmp_path, monkeypatch):
    store = _store(tmp_path)
    scenario_mod.save_scenario_record(store, _rubric(), {}, [])
    monkeypatch.setattr(scenario_mod, "boxes_dir", lambda: "")
    rows = scenario_mod.list_admin_scenarios(store)
    assert [(name, ver) for name, ver, _src in rows] == [("Uploaded", 1)]
    assert rows[0][2] == "engine"


def test_picker_merges_and_sorts_folder_and_uploads(tmp_path, monkeypatch):
    store = _store(tmp_path)
    scenario_mod.save_scenario_record(store, _rubric("Uploaded"), {}, [])
    boxes = tmp_path / "boxes"
    (boxes / "a-box").mkdir(parents=True)
    record = {"mode": "ranked", "rubric": _rubric("FromFolder"),
              "adversary": {}, "services": []}
    (boxes / "a-box" / "engine_record.json").write_text(json.dumps(record))
    monkeypatch.setattr(scenario_mod, "boxes_dir", lambda: str(boxes))
    rows = scenario_mod.list_admin_scenarios(store)
    assert [(n, v) for n, v, _ in rows] == [("FromFolder", 1), ("Uploaded", 1)]
    assert rows[0][2] == str(boxes / "a-box")
    assert rows[1][2] == "engine"


def test_folder_record_wins_the_dedupe_source(tmp_path, monkeypatch):
    store = _store(tmp_path)
    scenario_mod.save_scenario_record(store, _rubric("Same"), {}, [])
    boxes = tmp_path / "boxes"
    (boxes / "same-box").mkdir(parents=True)
    (boxes / "same-box" / "engine_record.json").write_text(json.dumps(
        {"mode": "ranked", "rubric": _rubric("Same"), "adversary": {},
         "services": []}))
    monkeypatch.setattr(scenario_mod, "boxes_dir", lambda: str(boxes))
    rows = scenario_mod.list_admin_scenarios(store)
    assert len(rows) == 1
    # Uploaded first, but the folder path still marks it as importable.
    assert rows[0][2] == "engine"
