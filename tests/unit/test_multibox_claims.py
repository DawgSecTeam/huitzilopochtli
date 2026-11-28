"""Multi-box claims, binds, and teardown (phase 2c).

The fake-portal idioms match tests/unit/test_claims.py. The invariant under
test is the plan's core promise: a single-scenario competition's claims,
pools, bind behavior and teardown are byte-identical to v1.1, and a
lineup's extra entries ride the same machinery per (competition, scenario).
"""
import time

import pytest

from common.schema import SCHEMA_VERSION
from engine import claims, competition, scenario as scenario_mod
from engine.store import Store


def _rubric(name):
    return {"schema_version": SCHEMA_VERSION, "scenario_name": name,
            "scenario_version": 1, "entries": []}


def _pool_spec(template):
    return {"template_vm_id": template, "template_vm_access_method": "ssh",
            "template_vm_username": "sysadmin",
            "template_vm_password": "asdf", "vm_count": 2}


SECRET = b"secret"


@pytest.fixture()
def store(tmp_path):
    s = Store(str(tmp_path / "engine.db"))
    scenario_mod.save_scenario_record(s, _rubric("MB-A"), {}, [],
                                      _pool_spec(201))
    scenario_mod.save_scenario_record(s, _rubric("MB-B"), {}, [],
                                      _pool_spec(202))
    scenario_mod.save_scenario_record(s, _rubric("MB-C"), {}, [],
                                      _pool_spec(203))
    return s


def _pin(store, comp, scenario_name, code, multi):
    name = claims.scenario_pool_name(comp.slug, scenario_name, multi)
    store.pin_competition_pool(comp.id, scenario_name, code, name)


@pytest.fixture()
def multi(store):
    c = competition.create_competition(
        store, slug="multi-comp", name="Multi Comp",
        scenario_name="MB-A", scenario_version=1, max_players=4,
        duration_s=3600, scenarios=[("MB-A", 1), ("MB-B", 1)])
    store.start_competition(c.id)
    c = store.get_competition(c.id)
    _pin(store, c, "MB-A", "CODEA", multi=True)
    _pin(store, c, "MB-B", "CODEB", multi=True)
    player, code, err = competition.create_player_with_code(
        store, c, "Alpha", SECRET)
    return c, store.get_player(player.player_id), code


@pytest.fixture()
def solo(store):
    c = competition.create_competition(
        store, slug="solo-comp", name="Solo Comp",
        scenario_name="MB-A", scenario_version=1, max_players=4,
        duration_s=3600)
    store.start_competition(c.id)
    c = store.get_competition(c.id)
    _pin(store, c, "MB-A", "CODESOLO", multi=False)
    player, code, err = competition.create_player_with_code(
        store, c, "Solo", SECRET)
    return c, store.get_player(player.player_id), code


@pytest.fixture(autouse=True)
def portal_env(monkeypatch):
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_URL", "http://portal")
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_SECRET", "s3cret")
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD", "pw")
    monkeypatch.setenv("HUITZILOPOCHTLI_AUTOWARM", "0")
    monkeypatch.setattr(claims, "_pin_is_alive", lambda *a, **k: True)


# --- claim fan-out ------------------------------------------------------------

def test_start_seat_claims_one_vm_per_lineup_entry(monkeypatch, store, multi):
    comp, player, code = multi
    seen = []

    def fake_claim(base, pool, code=None, secret=None, back_url=None,
                   timeout=None):
        seen.append((pool, code))
        return {"status": "ready", "open_url": f"http://portal/{pool}",
                "uid": f"u-{pool}", "expires_at": time.time() + 7200}

    monkeypatch.setattr(claims.workshop, "claim_vm", fake_claim)
    results = claims.start_seat(store, comp, player, back_url="x")
    assert len(results) == 2
    assert {p for p, _c in seen} == {"CODEA", "CODEB"}
    # The SAME seat code rides every box of the lineup (the box identifies
    # its own scenario; the code identifies the team).
    assert all(c == code for _p, c in seen)
    slots = {s.scenario_name: s for s in store.list_run_slots(player.player_id)}
    assert slots["MB-A"].claim_url == "http://portal/CODEA"
    assert slots["MB-B"].claim_url == "http://portal/CODEB"
    # The players mirror follows slot 0 only.
    p2 = store.get_player(player.player_id)
    assert p2.claim_url == "http://portal/CODEA"


def test_single_box_claim_uses_the_mirror_and_legacy_lock(monkeypatch,
                                                          store, solo):
    comp, player, code = solo
    seen = []

    def fake_claim(base, pool, code=None, secret=None, back_url=None,
                   timeout=None):
        seen.append(pool)
        return {"status": "ready", "open_url": "http://portal/one",
                "uid": "u1", "expires_at": time.time() + 7200}

    monkeypatch.setattr(claims.workshop, "claim_vm", fake_claim)
    out = claims.start_seat(store, comp, player, back_url="x")
    assert len(out) == 1 and seen == ["CODESOLO"]
    assert store.get_player(player.player_id).claim_url == "http://portal/one"


def test_ensure_pool_provisions_per_entry_names(monkeypatch, store):
    c = competition.create_competition(
        store, slug="prov", name="Prov", scenario_name="MB-A",
        scenario_version=1, max_players=2, duration_s=600,
        scenarios=[("MB-A", 1), ("MB-B", 1)])
    store.start_competition(c.id)
    provided = []

    monkeypatch.setattr(claims.workshop, "list_pools",
                        lambda *a, **k: [])

    def fake_provision(base, password, slug, spec, timeout=20.0,
                       pool_name=None):
        provided.append((pool_name, spec["template_vm_id"]))
        return {"job_id": "j", "pool_code": f"P{len(provided)}"}

    monkeypatch.setattr(claims.workshop, "provision_pool", fake_provision)
    pool, err = claims.ensure_pool(store, c, ("MB-B", 1))
    assert err is None and pool == "P1"
    assert provided == [("huitz-ranked-prov-mb-b", 202)]
    # Entry 0 keeps the legacy name so single-box conventions still hold:
    pool, err = claims.ensure_pool(store, c, ("MB-A", 1))
    assert provided[1] == ("huitz-ranked-prov-mb-a", 201)


def test_start_gate_checks_each_entry_against_its_own_template(
        store, multi, monkeypatch):
    """The start gate holds every lineup pool to its OWN entry's template:
    CODEB cloning 999 blocks the start naming MB-B, while a snapshot where
    each pool matches its entry starts clean."""
    comp, _player, _code = multi
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD", "pw")
    snapshot = {"status": "ok", "available": 4, "total": 4, "pools": 2,
                "templates": {"CODEA": 201, "CODEB": 999}}
    monkeypatch.setattr(claims, "live_pool_status",
                        lambda c, s=None: dict(snapshot))
    reason = claims.start_template_blocker(store, comp)
    assert reason and "CODEB clones template 999" in reason
    assert "MB-B's 202" in reason
    snapshot["templates"] = {"CODEA": 201, "CODEB": 202}
    assert claims.start_template_blocker(store, comp) is None


# --- bind routing ---------------------------------------------------------------

def test_multi_box_binds_start_one_clock_and_keep_the_code(store, multi):
    comp, player, code = multi
    ch = competition.hash_join_code(SECRET, code)
    st, p, _c = store.bind_player_box_atomic(ch, "bA", "pkA", "MB-A", 1,
                                             now=500.0)
    assert st == "ok"
    assert p.status == "running" and p.box_id == "bA"
    assert p.started_at == 500.0 and p.ends_at == 500.0 + comp.duration_s
    assert p.join_code_plain == code, "code stays live while a slot is free"
    # Re-joining the SAME scenario's slot is refused (still the live code).
    st, _p, _c = store.bind_player_box_atomic(ch, "bA2", "pk", "MB-A", 1,
                                              now=501.0)
    assert st == "already_joined"
    # Second box: same code, same clock, mirror stays position 0.
    st, p, _c = store.bind_player_box_atomic(ch, "bB", "pkB", "MB-B", 1,
                                             now=520.0)
    assert st == "ok"
    assert p.started_at == 500.0 and p.ends_at == 500.0 + comp.duration_s
    assert p.box_id == "bA"
    assert p.join_code_plain is None, "lineup complete: code burns"
    slots = {s.scenario_name: s for s in store.list_run_slots(p.player_id)}
    assert slots["MB-B"].box_id == "bB" and slots["MB-A"].box_id == "bA"
    # get_player_by_box resolves BOTH boxes to the seat.
    assert store.get_player_by_box("bA").player_id == p.player_id
    assert store.get_player_by_box("bB").player_id == p.player_id


def test_single_box_burns_the_code_on_first_bind(store, solo):
    comp, player, code = solo
    ch = competition.hash_join_code(SECRET, code)
    st, p, _c = store.bind_player_box_atomic(ch, "b1", "pk", "MB-A", 1,
                                             now=500.0)
    assert st == "ok"
    assert p.join_code_hash is None and p.join_code_plain is None
    assert p.box_id == "b1" and p.started_at == 500.0
    # The slot row mirrors it.
    slot = store.get_run_slot(p.player_id, "MB-A")
    assert slot.box_id == "b1" and slot.status == "running"


def test_foreign_scenario_box_is_refused(store, multi):
    comp, player, code = multi
    ch = competition.hash_join_code(SECRET, code)
    st, _p, _c = store.bind_player_box_atomic(ch, "bX", "pk", "MB-C", 1,
                                              now=500.0)
    assert st == "scenario_mismatch"


def test_wrong_version_of_a_lineup_scenario_is_refused(store, multi):
    comp, player, code = multi
    ch = competition.hash_join_code(SECRET, code)
    st, _p, _c = store.bind_player_box_atomic(ch, "bX", "pk", "MB-A", 9,
                                              now=500.0)
    assert st == "scenario_mismatch"


def test_finished_seat_cannot_bind_even_with_free_slot(store, multi):
    comp, player, code = multi
    ch = competition.hash_join_code(SECRET, code)
    st, p, _c = store.bind_player_box_atomic(ch, "bA", "pkA", "MB-A", 1,
                                             now=500.0)
    assert st == "ok"
    store.finish_player(p.player_id, now=600.0)
    st, _p, _c = store.bind_player_box_atomic(
        competition.hash_join_code(SECRET, code), "bB", "pkB", "MB-B", 1,
        now=610.0)
    assert st == "already_joined"


# --- sweep reaches a running seat's unbound slots --------------------------------

def test_sweep_retries_unbound_slot_of_a_running_seat(monkeypatch, store,
                                                      multi):
    comp, player, code = multi
    ch = competition.hash_join_code(SECRET, code)
    st, p, _c = store.bind_player_box_atomic(ch, "bA", "pkA", "MB-A", 1,
                                             now=500.0)
    assert st == "ok"
    claimed = []

    def fake_claim(base, pool, code=None, secret=None, back_url=None,
                    timeout=None):
        claimed.append(pool)
        return {"status": "ready", "open_url": f"http://portal/{pool}",
                "uid": f"u-{pool}", "expires_at": 9_000_000_000}

    monkeypatch.setattr(claims.workshop, "claim_vm", fake_claim)
    pass
    stats = {}
    claims._sweep_one(store, store.get_competition(comp.id), SECRET,
                      510.0, stats.setdefault("s", {
                          "retried": 0, "polled": 0, "rotated": 0,
                          "cleaned": 0, "auto_ended": 0, "deferred": 0,
                          "released_boxes": 0, "release_errors": 0,
                          "autowarmed": 0}))
    assert claimed == ["CODEB"], "the running seat's free slot got claimed"


# --- teardown loops every pin ---------------------------------------------------

def test_cleanup_tears_down_every_pool(monkeypatch, store, multi):
    comp, player, _code = multi
    released, destroyed, deleted = [], [], []
    pools = [
        {"code": "CODEA", "name": "huitz-ranked-multi-comp-mb-a",
         "count": 1, "total": 1, "available": 0, "in_use": 1,
         "config": {"template_vm_id": 201}},
        {"code": "CODEB", "name": "huitz-ranked-multi-comp-mb-b",
         "count": 1, "total": 1, "available": 0, "in_use": 1,
         "config": {"template_vm_id": 202}},
    ]
    monkeypatch.setattr(claims.workshop, "list_pools",
                        lambda *a, **k: pools)
    gone = set()
    monkeypatch.setattr(claims.workshop, "release_vm",
                        lambda base, uid: released.append(uid))
    monkeypatch.setattr(
        claims.workshop, "delete_pool",
        lambda base, password, code: deleted.append(code) or gone.add(code))
    monkeypatch.setattr(claims.workshop, "destroy_vms",
                        lambda base, password, vmids:
                        destroyed.append(tuple(vmids)) or
                        {"status": "done"})
    monkeypatch.setattr(
        claims, "_pool_vmids",
        lambda base, pw, name, code, expected=0, attempts=None:
        [] if code in gone else ([900] if code == "CODEA" else [901]))
    # Bind both so there are claimed VMs to release.
    for slot in store.list_run_slots(player.player_id):
        store.update_run_slot(slot.slot_id, claim_uid=f"u-{slot.scenario_name}")
    stats = claims.cleanup_pool(store, comp)
    assert stats["destroyed"] == 2 and stats["deleted"] is True
    assert set(deleted) == {"CODEA", "CODEB"}
    assert sorted(released) == ["u-MB-A", "u-MB-B"]
    fresh = store.get_competition(comp.id)
    assert fresh.workshop_pool_code is None
    assert all(code is None for _n, code, _nm
               in store.list_competition_pools(comp.id))


def test_cleanup_keeps_only_the_failed_pin(monkeypatch, store, multi):
    comp, _player, _code = multi
    pools = [
        {"code": "CODEA", "name": "huitz-ranked-multi-comp-mb-a", "count": 1},
        {"code": "CODEB", "name": "huitz-ranked-multi-comp-mb-b", "count": 1},
    ]
    monkeypatch.setattr(claims.workshop, "list_pools",
                        lambda *a, **k: pools)
    monkeypatch.setattr(claims.workshop, "release_vm", lambda *a, **k: None)

    def flaky_destroy(base, password, vmids):
        if 901 in vmids:
            raise claims.workshop.WorkshopError("portal busy")
        return {"status": "done"}

    monkeypatch.setattr(claims.workshop, "destroy_vms", flaky_destroy)
    monkeypatch.setattr(claims.workshop, "delete_pool",
                        lambda *a, **k: None)
    monkeypatch.setattr(claims, "_pool_vmids",
                        lambda base, pw, name, code, expected=0, attempts=None:
                        [900 if code == "CODEA" else 901])
    stats = claims.cleanup_pool(store, comp)
    rows = dict((n, c) for n, c, _nm in
                store.list_competition_pools(comp.id))
    assert rows["MB-A"] is None, "the cleaned pin is gone"
    assert rows["MB-B"] == "CODEB", "the failed pin survives for the retry"
