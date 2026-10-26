"""Tests for the ranked VM claim lifecycle (engine/claims.py) and the
per-competition pool provisioning (engine/workshop.py)."""
import time

import pytest

from common.schema import SCHEMA_VERSION
from engine import claims, competition, scenario as scenario_mod, workshop
from engine.store import Store


def _rubric(name="ClaimComp"):
    return {"schema_version": SCHEMA_VERSION, "scenario_name": name,
            "scenario_version": 1, "entries": []}


def _pool_spec(template=174):
    return {"template_vm_id": template, "template_vm_access_method": "ssh",
            "template_vm_username": "sysadmin", "template_vm_password": "asdf",
            "vm_count": 2}


@pytest.fixture()
def store(tmp_path):
    s = Store(str(tmp_path / "engine.db"))
    scenario_mod.save_scenario_record(s, _rubric(), {}, [])
    scenario_mod.save_scenario_record(s, _rubric("ClaimCompPool"), {}, [],
                                      _pool_spec())
    return s


@pytest.fixture()
def comp(store):
    c = competition.create_competition(
        store, slug="claim-comp", name="Claim Comp",
        scenario_name="ClaimComp", scenario_version=1,
        max_players=8, duration_s=3600, workshop_pool_code="POOL1")
    store.start_competition(c.id)
    return store.get_competition(c.id)


@pytest.fixture()
def comp_provisioned(store):
    """A live competition whose scenario carries a pool block and no pin."""
    c = competition.create_competition(
        store, slug="provision-me", name="Provision Me",
        scenario_name="ClaimCompPool", scenario_version=1,
        max_players=8, duration_s=3600)
    store.start_competition(c.id)
    return store.get_competition(c.id)


@pytest.fixture()
def player(store, comp):
    p, _code, err = competition.create_player_with_code(
        store, comp, "Ada", b"secret")
    assert err is None
    return store.get_player(p.player_id)


@pytest.fixture(autouse=True)
def portal_env(monkeypatch):
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_URL", "http://portal")
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_SECRET", "s3cret")


# --- pool provisioning client -------------------------------------------------


def _portal_pool(code, name, template=174):
    """A /api/admin/pools row in the live portal's shape."""
    return {"code": code, "name": name, "available": 0, "total": 0,
            "in_use": 0, "last_used": 0, "count": 2,
            "config": {"template_vm_id": template, "pool_name": name,
                       "pool_code": code}}


def test_competition_pool_name_is_deterministic():
    assert workshop.competition_pool_name("cocoa-falls-demo") == \
        "huitz-ranked-cocoa-falls-demo"


def test_find_pool_by_name_matches_the_portal_row():
    pools = [_portal_pool("AAAAA", "other"), _portal_pool("BBBBB", "mine")]
    assert workshop.find_pool_by_name(pools, "mine")["code"] == "BBBBB"
    assert workshop.find_pool_by_name(pools, "nope") is None
    assert workshop.find_pool_by_name(["junk"], "mine") is None


def test_provision_pool_passes_the_spec_and_captures_the_code(monkeypatch):
    sent = {}

    def fake_call(base, method, path, body, timeout, **kw):
        sent.update(body, _method=method, _path=path)
        return {"job_id": "j1"}

    monkeypatch.setattr(workshop, "_call", fake_call)
    monkeypatch.setattr(workshop, "list_pools",
                        lambda *a, **kw: [_portal_pool("NEWPW",
                                                       "huitz-ranked-x")])
    out = workshop.provision_pool("http://portal", "pw", "x",
                                  _pool_spec(template=183))
    assert out == {"job_id": "j1", "pool_code": "NEWPW"}
    assert (sent["_method"], sent["_path"]) == ("POST", "/api/admin/provision")
    assert sent["pool_name"] == "huitz-ranked-x"
    assert sent["template_vm_id"] == 183
    assert sent["template_vm_password"] == "asdf"
    assert sent["vm_count"] == 2 and sent["guac_link_ttl_seconds"] == 7200
    assert sent["dispenser"] is True and sent["private"] is True
    assert sent["group"] == "Challenge"


# --- ensure_pool (per-competition provisioning) ---------------------------------


def test_ensure_pool_keeps_an_existing_pin(store, comp, monkeypatch):
    def boom(*a, **kw):
        raise AssertionError("a pinned competition must not touch the portal")

    monkeypatch.setattr(claims.workshop, "list_pools", boom)
    assert claims.ensure_pool(store, comp) == ("POOL1", None)


def test_ensure_pool_provisions_a_dedicated_pool(store, comp_provisioned,
                                                 monkeypatch):
    created = []

    def fake_provision(base, password, slug, spec, **kw):
        created.append((base, password, slug, spec))
        return {"job_id": "j1", "pool_code": "NEWP1"}

    monkeypatch.setattr(claims.workshop, "provision_pool", fake_provision)
    monkeypatch.setattr(claims.workshop, "list_pools", lambda *a, **kw: [])
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD", "pw")
    code, err = claims.ensure_pool(store, comp_provisioned)
    assert (code, err) == ("NEWP1", None)
    base, password, slug, spec = created[0]
    assert (base, password, slug) == ("http://portal", "pw", "provision-me")
    assert spec["template_vm_id"] == 174
    assert store.get_competition(comp_provisioned.id).workshop_pool_code == "NEWP1"


def test_ensure_pool_reuses_its_own_pool_after_a_restart(store,
                                                         comp_provisioned,
                                                         monkeypatch):
    provisions = []
    monkeypatch.setattr(claims.workshop, "provision_pool",
                        lambda *a, **kw: provisions.append(1))
    monkeypatch.setattr(
        claims.workshop, "list_pools",
        lambda *a, **kw: [_portal_pool("NEWP1", "huitz-ranked-provision-me")])
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD", "pw")
    assert claims.ensure_pool(store, comp_provisioned) == ("NEWP1", None)
    assert provisions == []
    assert store.get_competition(comp_provisioned.id).workshop_pool_code == "NEWP1"


def test_ensure_pool_refuses_a_same_name_pool_from_the_wrong_template(
        store, comp_provisioned, monkeypatch):
    monkeypatch.setattr(
        claims.workshop, "list_pools",
        lambda *a, **kw: [_portal_pool("NEWP1", "huitz-ranked-provision-me",
                                       template=999)])
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD", "pw")
    code, err = claims.ensure_pool(store, comp_provisioned)
    assert code is None and "clones template 999" in err
    assert store.get_competition(comp_provisioned.id).workshop_pool_code is None


def test_ensure_pool_reports_a_busy_portal_and_retries_later(
        store, comp_provisioned, monkeypatch):
    monkeypatch.setattr(claims.workshop, "list_pools", lambda *a, **kw: [])

    def boom(*a, **kw):
        raise workshop.WorkshopError("A provision job is already running.")

    monkeypatch.setattr(claims.workshop, "provision_pool", boom)
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD", "pw")
    code, err = claims.ensure_pool(store, comp_provisioned)
    assert code is None and "already running" in err
    assert store.get_competition(comp_provisioned.id).workshop_pool_code is None


def test_ensure_pool_needs_a_pool_block(store, comp, monkeypatch):
    store.update_competition(comp.id, workshop_pool_code=None)
    comp = store.get_competition(comp.id)
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD", "pw")
    code, err = claims.ensure_pool(store, comp)
    assert code is None and "no pool provisioning block" in err


def test_ensure_pool_needs_the_admin_password(store, comp_provisioned,
                                              monkeypatch):
    code, err = claims.ensure_pool(store, comp_provisioned)
    assert code is None and "admin password" in err


# --- claim lifecycle ---------------------------------------------------------


def _claim_ok(monkeypatch, **over):
    result = {"open_url": "http://portal/r/u1", "url": "http://guac/raw",
              "uid": "u1", "expires_at": time.time() + 7200}
    result.update(over)
    calls = []

    def fake(*a, **kw):
        calls.append((a, kw))
        return result

    monkeypatch.setattr(claims.workshop, "claim_vm", fake)
    return calls, result


def test_start_stores_the_stable_open_link(store, comp, player, monkeypatch):
    calls, _ = _claim_ok(monkeypatch)
    out = claims.start(store, comp, player, back_url="http://engine/back")
    assert out["ok"] and out["url"] == "http://portal/r/u1"
    fresh = store.get_player(player.player_id)
    assert fresh.claim_url == "http://portal/r/u1"
    assert fresh.claim_uid == "u1"
    assert fresh.claim_ticket is None
    assert fresh.claim_error is None
    kw = calls[0][1]
    assert kw["code"] == player.join_code_plain
    assert kw["secret"] == "s3cret"
    assert kw["back_url"] == "http://engine/back"


def test_start_records_a_portal_failure_for_the_page(store, comp, player,
                                                     monkeypatch):
    def boom(*a, **kw):
        raise workshop.WorkshopError("No VMs available right now.")

    monkeypatch.setattr(claims.workshop, "claim_vm", boom)
    out = claims.start(store, comp, player)
    assert not out["ok"]
    fresh = store.get_player(player.player_id)
    assert "No VMs available" in fresh.claim_error
    assert fresh.claim_attempts == 1
    assert fresh.claim_url is None


def test_start_falls_back_when_the_portal_has_no_prebind_secret(store, comp,
                                                                player,
                                                                monkeypatch):
    calls = []

    def fake(base, pool_code, **kw):
        calls.append(kw)
        if kw.get("secret"):
            raise workshop.WorkshopError(
                "Prebind is disabled: HUITZ_PREBIND_SECRET is not set on the portal.")
        return {"url": "http://guac/raw", "uid": "u9"}

    monkeypatch.setattr(claims.workshop, "claim_vm", fake)
    out = claims.start(store, comp, player)
    assert out["ok"] and out["url"] == "http://guac/raw"
    assert len(calls) == 2 and calls[1].get("secret") is None
    fresh = store.get_player(player.player_id)
    assert fresh.claim_url == "http://guac/raw"
    assert fresh.claim_error is None


def test_start_provisions_a_pool_when_the_competition_has_none(
        store, comp_provisioned, monkeypatch):
    p, _code, err = competition.create_player_with_code(
        store, comp_provisioned, "Ada", b"secret")
    assert err is None
    calls, result = _claim_ok(monkeypatch)
    monkeypatch.setattr(claims.workshop, "list_pools", lambda *a, **kw: [])
    monkeypatch.setattr(claims.workshop, "provision_pool",
                        lambda *a, **kw: {"job_id": "j1", "pool_code": "NEWP1"})
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD", "pw")
    out = claims.start(store, comp_provisioned, store.get_player(p.player_id))
    assert out["ok"] and out["url"] == result["open_url"]
    assert calls[0][0][:2] == ("http://portal", "NEWP1")
    # The provisioned pool is pinned on the competition for later players.
    assert store.get_competition(comp_provisioned.id).workshop_pool_code == "NEWP1"


def test_start_records_why_no_pool_could_be_provisioned(store, comp, player,
                                                        monkeypatch):
    store.update_competition(comp.id, workshop_pool_code=None)
    comp = store.get_competition(comp.id)

    def boom(*a, **kw):
        raise AssertionError("portal claim must not run without a pool")

    monkeypatch.setattr(claims.workshop, "claim_vm", boom)
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD", "pw")
    out = claims.start(store, comp, player)
    assert not out["ok"]
    assert "no pool provisioning block" in \
        store.get_player(player.player_id).claim_error


def test_start_stores_a_provisioning_ticket(store, comp, player, monkeypatch):
    monkeypatch.setattr(claims.workshop, "claim_vm",
                        lambda *a, **kw: {"status": "provisioning",
                                          "ticket": "t1"})
    out = claims.start(store, comp, player)
    assert out["ok"] and out["pending"]
    fresh = store.get_player(player.player_id)
    assert fresh.claim_ticket == "t1" and fresh.claim_url is None


def test_poll_is_throttled_but_force_bypasses_it(store, comp, player,
                                                 monkeypatch):
    store.update_player(player.player_id, claim_ticket="t1")
    player = store.get_player(player.player_id)
    calls = []
    state = {"ready": False}

    def fake(base, ticket, **kw):
        calls.append(ticket)
        if state["ready"]:
            return {"status": "ready", "open_url": "http://portal/r/u1",
                    "uid": "u1"}
        return {"status": "provisioning", "stage": "cloning"}

    monkeypatch.setattr(claims.workshop, "poll_ticket", fake)
    now = time.time()
    claims.poll(store, player, now=now)
    assert calls == ["t1"]
    # Immediately again: throttled.
    claims.poll(store, store.get_player(player.player_id), now=now + 0.5)
    assert calls == ["t1"]
    state["ready"] = True
    claims.poll(store, store.get_player(player.player_id), now=now + 0.5,
                force=True)
    assert calls == ["t1", "t1"]
    assert store.get_player(player.player_id).claim_url == "http://portal/r/u1"


def test_poll_stops_after_a_terminal_ticket_error(store, comp, player,
                                                  monkeypatch):
    store.update_player(player.player_id, claim_ticket="t1")
    monkeypatch.setattr(claims.workshop, "poll_ticket",
                        lambda *a, **kw: {"status": "error",
                                          "detail": "clone failed"})
    fresh = claims.poll(store, store.get_player(player.player_id), force=True)
    assert fresh.claim_ticket is None
    assert "clone failed" in fresh.claim_error


def test_poll_does_nothing_once_the_box_is_bound(store, comp, player,
                                                 monkeypatch):
    store.update_player(player.player_id, claim_ticket="t1", box_id="box-1")
    monkeypatch.setattr(claims.workshop, "poll_ticket",
                        lambda *a, **kw: (_ for _ in ()).throw(
                            AssertionError("must not poll a bound slot")))
    claims.poll(store, store.get_player(player.player_id), force=True)


# --- code rotation -----------------------------------------------------------


def test_fresh_code_is_not_rotated(store, comp, player, monkeypatch):
    _claim_ok(monkeypatch)
    claims.start(store, comp, player)
    monkeypatch.setattr(claims.workshop, "push_prebind",
                        lambda *a, **kw: (_ for _ in ()).throw(
                            AssertionError("must not rotate")))
    fresh = store.get_player(player.player_id)
    assert not claims.rotate_code_if_needed(store, fresh, b"secret")


def test_failed_rotation_keeps_the_code_the_player_may_have(store, comp,
                                                            player,
                                                            monkeypatch):
    _claim_ok(monkeypatch)
    claims.start(store, comp, player)
    store.update_player(player.player_id, join_code_expires_at=time.time() + 5)
    original = store.get_player(player.player_id)

    def boom(*a, **kw):
        raise workshop.WorkshopError("portal unreachable")

    monkeypatch.setattr(claims.workshop, "push_prebind", boom)
    assert not claims.rotate_code_if_needed(store, original, b"secret")
    after = store.get_player(player.player_id)
    assert after.join_code_plain == original.join_code_plain
    assert after.join_code_expires_at == original.join_code_expires_at


def test_near_expiry_code_is_rotated_and_pushed(store, comp, player,
                                                monkeypatch):
    _claim_ok(monkeypatch)
    claims.start(store, comp, player)
    store.update_player(player.player_id, join_code_expires_at=time.time() + 5)
    pushed = []
    monkeypatch.setattr(claims.workshop, "push_prebind",
                        lambda base, uid, code, **kw: pushed.append(
                            (base, uid, code, kw)))
    fresh = store.get_player(player.player_id)
    assert claims.rotate_code_if_needed(store, fresh, b"secret",
                                        back_url="http://engine/back")
    assert len(pushed) == 1
    base, uid, code, kw = pushed[0]
    assert (base, uid) == ("http://portal", "u1")
    assert code != player.join_code_plain
    assert kw["secret"] == "s3cret"
    assert kw["back_url"] == "http://engine/back"
    updated = store.get_player(player.player_id)
    assert updated.join_code_plain == code
    assert updated.join_code_expires_at > time.time() + 1700


# --- sweep (automatic dispensing) -----------------------------------------------


def test_sweep_retries_a_failed_claim_after_backoff(store, comp, player,
                                                    monkeypatch):
    store.update_player(player.player_id, claim_error="portal unreachable",
                        claim_attempts=1,
                        claim_last_attempt_at=time.time() - 999)
    calls, result = _claim_ok(monkeypatch)
    stats = claims.sweep(store, b"secret")
    assert stats["retried"] == 1
    assert calls
    fresh = store.get_player(player.player_id)
    assert fresh.claim_url == result["open_url"]
    assert fresh.claim_error is None


def test_sweep_respects_the_retry_backoff(store, comp, player, monkeypatch):
    store.update_player(player.player_id, claim_error="portal unreachable",
                        claim_attempts=2,
                        claim_last_attempt_at=time.time() - 10)
    monkeypatch.setattr(claims.workshop, "claim_vm",
                        lambda *a, **kw: (_ for _ in ()).throw(
                            AssertionError("too soon")))
    assert claims.sweep(store, b"secret")["retried"] == 0


def test_sweep_refreshes_an_expired_join_code_before_retrying(store, comp,
                                                              player,
                                                              monkeypatch):
    store.update_player(player.player_id, claim_error="portal unreachable",
                        claim_attempts=1,
                        claim_last_attempt_at=time.time() - 999,
                        join_code_expires_at=time.time() - 5)
    calls, _ = _claim_ok(monkeypatch)
    claims.sweep(store, b"secret")
    fresh = store.get_player(player.player_id)
    assert fresh.join_code_plain != player.join_code_plain
    assert fresh.join_code_expires_at > time.time() + 1700
    assert calls[0][1]["code"] == fresh.join_code_plain


def test_sweep_polls_pending_tickets(store, comp, player, monkeypatch):
    store.update_player(player.player_id, claim_ticket="t1")
    polls = []

    def fake(base, ticket, **kw):
        polls.append(ticket)
        return {"status": "ready", "open_url": "http://portal/r/u1", "uid": "u1"}

    monkeypatch.setattr(claims.workshop, "poll_ticket", fake)
    stats = claims.sweep(store, b"secret")
    assert stats["polled"] == 1 and polls == ["t1"]
    assert store.get_player(player.player_id).claim_url == "http://portal/r/u1"


def test_sweep_rotates_an_expiring_code_on_claimed_vms(store, comp, player,
                                                       monkeypatch):
    _claim_ok(monkeypatch)
    claims.start(store, comp, player)
    store.update_player(player.player_id, join_code_expires_at=time.time() + 5)
    pushed = []
    monkeypatch.setattr(claims.workshop, "push_prebind",
                        lambda base, uid, code, **kw: pushed.append(code))
    stats = claims.sweep(store, b"secret")
    assert stats["rotated"] == 1 and len(pushed) == 1


def test_sweep_does_nothing_without_a_portal(store, comp, player, monkeypatch):
    monkeypatch.delenv("HUITZILOPOCHTLI_WORKSHOP_URL")
    monkeypatch.setattr(claims.workshop, "claim_vm",
                        lambda *a, **kw: (_ for _ in ()).throw(
                            AssertionError("no portal")))
    assert claims.sweep(store, b"secret") == {"retried": 0, "polled": 0,
                                              "rotated": 0, "cleaned": 0}


def test_sweep_skips_bound_and_running_players(store, comp, player,
                                               monkeypatch):
    store.update_player(player.player_id, box_id="box-1", status="running")

    def boom(*a, **kw):
        raise AssertionError("must not touch a bound player")

    monkeypatch.setattr(claims.workshop, "claim_vm", boom)
    monkeypatch.setattr(claims.workshop, "poll_ticket", boom)
    monkeypatch.setattr(claims.workshop, "push_prebind", boom)
    assert claims.sweep(store, b"secret") == {"retried": 0, "polled": 0,
                                              "rotated": 0, "cleaned": 0}


# --- pool cleanup (competition end) --------------------------------------------


def test_cleanup_pool_releases_and_deletes_its_own_pool(store,
                                                        comp_provisioned,
                                                        monkeypatch):
    released, deleted = [], []
    p, _code, _err = competition.create_player_with_code(
        store, comp_provisioned, "Ada", b"secret")
    store.update_player(p.player_id, claim_uid="u1")
    monkeypatch.setattr(
        claims.workshop, "list_pools",
        lambda *a, **kw: [_portal_pool("OWNP1", "huitz-ranked-provision-me")])
    monkeypatch.setattr(claims.workshop, "release_vm",
                        lambda base, uid: released.append(uid))
    monkeypatch.setattr(claims.workshop, "delete_pool",
                        lambda base, pw, code, **kw: deleted.append(code))
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD", "pw")
    store.update_competition(comp_provisioned.id, workshop_pool_code="OWNP1")
    stats = claims.cleanup_pool(store,
                                store.get_competition(comp_provisioned.id))
    assert stats["released"] == 1 and stats["deleted"] is True
    assert released == ["u1"] and deleted == ["OWNP1"]
    fresh = store.get_competition(comp_provisioned.id)
    assert fresh.workshop_pool_code is None


def test_cleanup_pool_releases_bound_boxes_too(store, comp_provisioned,
                                               monkeypatch):
    released = []
    p, _code, _err = competition.create_player_with_code(
        store, comp_provisioned, "Ada", b"secret")
    store.update_player(p.player_id, claim_uid="u1", box_id="box-1",
                        status="finished")
    monkeypatch.setattr(
        claims.workshop, "list_pools",
        lambda *a, **kw: [_portal_pool("OWNP1", "huitz-ranked-provision-me")])
    monkeypatch.setattr(claims.workshop, "release_vm",
                        lambda base, uid: released.append(uid))
    monkeypatch.setattr(claims.workshop, "delete_pool", lambda *a, **kw: None)
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD", "pw")
    store.update_competition(comp_provisioned.id, workshop_pool_code="OWNP1")
    stats = claims.cleanup_pool(store,
                                store.get_competition(comp_provisioned.id))
    assert stats["released"] == 1


def test_cleanup_pool_leaves_a_pre_existing_shared_pool_alone(store, comp,
                                                              monkeypatch):
    released, deleted = [], []
    monkeypatch.setattr(claims.workshop, "list_pools",
                        lambda *a, **kw: [_portal_pool("POOL1",
                                                       "Chocolate Factory")])
    monkeypatch.setattr(claims.workshop, "release_vm",
                        lambda base, uid: released.append(uid))
    monkeypatch.setattr(claims.workshop, "delete_pool",
                        lambda *a, **kw: deleted.append(1))
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD", "pw")
    stats = claims.cleanup_pool(store, comp)
    assert stats["legacy"] is True and stats["deleted"] is False
    assert released == [] and deleted == []
    # The pin is still cleared so the competition never uses the pool again.
    assert store.get_competition(comp.id).workshop_pool_code is None


def test_cleanup_pool_keeps_the_pin_while_the_portal_is_down(store, comp,
                                                             monkeypatch):
    def boom(*a, **kw):
        raise workshop.WorkshopError("down")

    monkeypatch.setattr(claims.workshop, "list_pools", boom)
    monkeypatch.setenv("HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD", "pw")
    assert claims.cleanup_pool(store, comp)["deleted"] is False
    assert store.get_competition(comp.id).workshop_pool_code == "POOL1"


def test_cleanup_pool_without_a_portal_clears_the_pin(store, comp,
                                                      monkeypatch):
    monkeypatch.delenv("HUITZILOPOCHTLI_WORKSHOP_URL")
    stats = claims.cleanup_pool(store, comp)
    assert stats == {"released": 0, "deleted": False, "legacy": False}
    assert store.get_competition(comp.id).workshop_pool_code is None


def test_sweep_cleans_up_an_ended_competitions_pool(store, comp, monkeypatch):
    cleaned = []
    monkeypatch.setattr(claims, "cleanup_pool",
                        lambda s, c: cleaned.append(c.id)
                        or {"released": 0, "deleted": True})
    store.end_competition(comp.id)
    stats = claims.sweep(store, b"secret")
    assert stats["cleaned"] == 1 and cleaned == [comp.id]


# --- reclaim -----------------------------------------------------------------


def test_reclaim_releases_the_old_vm_then_claims_a_new_one(store, comp, player,
                                                           monkeypatch):
    _claim_ok(monkeypatch)
    claims.start(store, comp, player)
    released, claimed = [], []
    monkeypatch.setattr(claims.workshop, "release_vm",
                        lambda base, uid: released.append(uid))
    monkeypatch.setattr(claims.workshop, "claim_vm",
                        lambda *a, **kw: claimed.append(1) or {
                            "open_url": "http://portal/r/u2", "uid": "u2"})
    fresh = store.get_player(player.player_id)
    out = claims.reclaim(store, comp, fresh)
    assert out["ok"] and out["url"] == "http://portal/r/u2"
    assert released == ["u1"]
    assert claimed == [1]
    assert store.get_player(player.player_id).claim_uid == "u2"


def test_reclaim_refuses_a_bound_slot(store, comp, player):
    store.update_player(player.player_id, box_id="box-1")
    fresh = store.get_player(player.player_id)
    assert not claims.reclaim(store, comp, fresh)["ok"]


def test_reclaim_refuses_after_the_competition_ended(store, comp, player,
                                                     monkeypatch):
    monkeypatch.setattr(claims.workshop, "claim_vm",
                        lambda *a, **kw: (_ for _ in ()).throw(
                            AssertionError("must not claim")))
    store.end_competition(comp.id)
    ended = store.get_competition(comp.id)
    out = claims.reclaim(store, ended, player)
    assert not out["ok"] and "no longer live" in out["error"]


# --- misc --------------------------------------------------------------------


def test_describe_never_exposes_the_join_code(store, comp, player):
    info = claims.describe(player)
    assert "join_code" not in info
    assert info["box_bound"] is False


def test_player_csrf_round_trip():
    token = claims.player_csrf(b"secret", "p1")
    assert claims.check_csrf(b"secret", "p1", token)
    assert not claims.check_csrf(b"secret", "p2", token)
    assert not claims.check_csrf(b"secret", "p1", "nope")
    assert not claims.check_csrf(b"secret", "p1", "")
