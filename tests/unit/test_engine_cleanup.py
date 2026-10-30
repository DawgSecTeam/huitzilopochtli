import json

from engine import cleanup, competition, scenario as scenario_mod
from engine.store import Store


def _store(tmp_path):
    store = Store(str(tmp_path / "engine.db"))
    scenario_mod.save_scenario_record(store, {
        "schema_version": 1, "scenario_name": "S", "scenario_version": 1,
        "entries": []}, {}, [])
    comp = competition.create_competition(
        store, slug="clean-me", name="Clean Me", scenario_name="S",
        scenario_version=1, max_players=4, duration_s=600,
        workshop_pool_code="POOL1")
    return store, comp


def test_dry_run_reports_the_pin(tmp_path, capsys):
    store, comp = _store(tmp_path)
    rc = cleanup.main(["--slug", "clean-me", "--db", str(tmp_path / "engine.db"),
                       "--dry-run"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["pool"] == "POOL1" and out["dry_run"] is True


def test_cleanup_calls_the_shared_teardown(tmp_path, capsys, monkeypatch):
    store, comp = _store(tmp_path)
    seen = []

    def fake(store_arg, comp_arg):
        seen.append(comp_arg.slug)
        return {"released": 0, "destroyed": 2, "deleted": True}

    monkeypatch.setattr(cleanup.claims, "cleanup_pool", fake)
    rc = cleanup.main(["--slug", "clean-me", "--db", str(tmp_path / "engine.db")])
    assert rc == 0 and seen == ["clean-me"]
    out = json.loads(capsys.readouterr().out)
    assert out["destroyed"] == 2 and out["deleted"] is True


def test_missing_slug_is_an_error(tmp_path, capsys):
    _store(tmp_path)
    rc = cleanup.main(["--slug", "nope", "--db", str(tmp_path / "engine.db")])
    assert rc == 1
    assert "no competition" in capsys.readouterr().out
