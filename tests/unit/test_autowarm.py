"""Tests for auto-warm: keeping a buffer of unclaimed VMs in each live
competition's pool (engine/claims.autowarm_tick)."""
import pytest

from common.schema import SCHEMA_VERSION
from engine import claims, competition, scenario as scenario_mod
from engine.store import Store


def _rubric(name="WarmComp"):
    return {"schema_version": SCHEMA_VERSION, "scenario_name": name,
            "scenario_version": 1, "entries": []}


@pytest.fixture()
def store(tmp_path, monkeypatch):
    monkeypatch.delenv("HUITZILOPOCHTLI_WORKSHOP_URL", raising=False)
    monkeypatch.delenv("HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD",
                       raising=False)
    monkeypatch.delenv("HUITZILOPOCHTLI_AUTOWARM", raising=False)
    monkeypatch.delenv("HUITZILOPOCHTLI_AUTOWARM_TARGET", raising=False)
    s = Store(str(tmp_path / "engine.db"))
    scenario_mod.save_scenario_record(s, _rubric(), {}, [])
    c = competition.create_competition(
        s, slug="warm-comp", name="Warm Comp", scenario_name="WarmComp",
        scenario_version=1, max_players=8, duration_s=3600,
        workshop_pool_code="POOL1")
    s.start_competition(c.id)
    s.orig_comp_id = c.id  # noqa -- attached for tests' convenience
    return s


def _live_comp(store):
    return store.get_competition(store.orig_comp_id)


def test_target_default_is_2(monkeypatch):
    assert claims.autowarm_target() == 2


def test_target_env_and_disable(monkeypatch):
    monkeypatch.setenv("HUITZILOPOCHTLI_AUTOWARM_TARGET", "5")
    assert claims.autowarm_target() == 5
    monkeypatch.setenv("HUITZILOPOCHTLI_AUTOWARM_TARGET", "junk")
    assert claims.autowarm_target() == 2
    monkeypatch.setenv("HUITZILOPOCHTLI_AUTOWARM", "0")
    assert not claims.autowarm_enabled()


def test_refills_to_target(store, monkeypatch):
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_URL", "http://portal")
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD", "pw")
    calls = []

    monkeypatch.setattr(claims.workshop, "pool_snapshot",
                        lambda *a, **k: {"available": 0, "total": 2})
    monkeypatch.setattr(claims.workshop, "provision_more",
                        lambda *a, **k: calls.append(a) or {})
    got = claims.autowarm_tick(store, _live_comp(store))
    assert got == 2 and calls, "deficit of 2 must be requested"
    assert calls[-1][3] == 2  # (base, password, pool_code, count)


def test_no_request_when_buffer_met(store, monkeypatch):
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_URL", "http://portal")
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD", "pw")
    monkeypatch.setattr(claims.workshop, "pool_snapshot",
                        lambda *a, **k: {"available": 2, "total": 4})
    called = False

    def _boom(*a, **k):
        nonlocal called
        called = True

    monkeypatch.setattr(claims.workshop, "provision_more", _boom)
    assert claims.autowarm_tick(store, _live_comp(store)) == 0
    assert not called


def test_cooldown_stacks_no_jobs(store, monkeypatch):
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_URL", "http://portal")
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD", "pw")
    monkeypatch.setattr(claims.workshop, "pool_snapshot",
                        lambda *a, **k: {"available": 0, "total": 2})
    calls = []
    monkeypatch.setattr(claims.workshop, "provision_more",
                        lambda *a, **k: calls.append(1) or {})
    now = 1000.0
    assert claims.autowarm_tick(store, _live_comp(store), now=now) > 0
    assert claims.autowarm_tick(store, _live_comp(store), now=now + 1) == 0
    assert len(calls) == 1
    # After the cooldown it refills again.
    assert claims.autowarm_tick(
        store, _live_comp(store),
        now=now + claims.AUTOWARM_COOLDOWN_S + 1) > 0
    assert len(calls) == 2


def test_force_bypasses_cooldown(store, monkeypatch):
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_URL", "http://portal")
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD", "pw")
    monkeypatch.setattr(claims.workshop, "pool_snapshot",
                        lambda *a, **k: {"available": 0, "total": 2})
    calls = []
    monkeypatch.setattr(claims.workshop, "provision_more",
                        lambda *a, **k: calls.append(1) or {})
    now = 1000.0
    claims.autowarm_tick(store, _live_comp(store), now=now)
    claims.autowarm_tick(store, _live_comp(store), now=now + 1, force=True)
    assert len(calls) == 2


def test_disabled_or_unconfigured_is_a_no_op(store, monkeypatch):
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_URL", "http://portal")
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD", "pw")
    # Feature off:
    monkeypatch.setenv("HUITZILOPOCHTLI_AUTOWARM", "0")
    assert claims.autowarm_tick(store, _live_comp(store)) == 0
    monkeypatch.delenv("HUITZILOPOCHTLI_AUTOWARM")
    # Target 0:
    monkeypatch.setenv("HUITZILOPOCHTLI_AUTOWARM_TARGET", "0")
    assert claims.autowarm_tick(store, _live_comp(store)) == 0
    monkeypatch.delenv("HUITZILOPOCHTLI_AUTOWARM_TARGET")
    # Portal not configured:
    monkeypatch.delenv("HUITZILOPOCHTLI_WORKSHOP_URL")
    assert claims.autowarm_tick(store, _live_comp(store)) == 0
    # No pinned pool:
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_URL", "http://portal")
    comp = _live_comp(store)
    store.update_competition(comp.id, workshop_pool_code=None)
    assert claims.autowarm_tick(store, store.get_competition(comp.id)) == 0


def test_ended_competition_never_warms(store, monkeypatch):
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_URL", "http://portal")
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD", "pw")
    comp = _live_comp(store)
    store.end_competition(comp.id)
    monkeypatch.setattr(claims.workshop, "pool_snapshot",
                        lambda *a, **k: {"available": 0, "total": 2})
    assert claims.autowarm_tick(store, store.get_competition(comp.id)) == 0


def test_portal_error_is_swallowed(store, monkeypatch):
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_URL", "http://portal")
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD", "pw")

    def _fail(*a, **k):
        raise claims.workshop.WorkshopError("portal down")

    monkeypatch.setattr(claims.workshop, "pool_snapshot", _fail)
    assert claims.autowarm_tick(store, _live_comp(store)) == 0
