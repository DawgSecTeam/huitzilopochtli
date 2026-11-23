"""VM claim lifecycle for ranked joins.

A player slot owns at most one VM. The engine asks the workshop portal for it
(``POST /api/claim``) and stores the portal's *open* link, which is stable:
the portal mints a fresh Guacamole session every time it is opened. With the
prebind secret configured, the engine also hands the portal the player's
one-time join code, so the portal can run ``huitz join`` inside the guest on
the first open -- the player never types anything.

Each competition provisions its own portal pool (``ensure_pool``), cloned from
the ranked template named in the scenario record's ``pool`` block; the engine
never selects among the portal's pre-existing pools.

This module owns the retry/backoff and code-rotation policy. It never raises:
every failure is recorded on the player row (``claim_error``) so the join page
can show what happened and offer a retry.
"""
import hashlib
import hmac
import json
import os
import re
import threading
import time
from typing import Optional

from engine import competition, scenario as scenario_mod, workshop
from engine.store import (CompetitionRecord, JoinCodeCollision, PlayerRecord,
                          Store)

POLL_MIN_INTERVAL = 3.0
MAX_POLL_BACKOFF = 30.0
RETRY_MIN_INTERVAL = 15.0
MAX_RETRY_BACKOFF = 300.0
CODE_TTL_S = 1800
CODE_REFRESH_MARGIN = 600.0

#: Admin pre-deploy: how many boxes one click may ask the portal to warm and
#: how long the background job waits for them to register. A cold Windows
#: clone takes ~60-180 s to answer RDP, and the portal provisions ten at a
#: time, so 30 boxes can legitimately take several minutes.
WARM_MAX = 200
WARM_WAIT_S = 2400.0

#: comp id -> background warm job state. Process-local on purpose: it is a
#: progress indicator for the admin page, not durable competition state (the
#: pin and the portal's own pool are the source of truth).
_WARM_JOBS = {}
_WARM_LOCK = threading.Lock()

#: One provisioning attempt per **competition** at a time. Concurrent first
#: claims on a fresh competition used to race the portal's single provision
#: job; the losers could pin a pool whose config another call had just
#: deleted (live load test: 15 simultaneous joins produced a permanently
#: stale pool pin and "Unknown code." for every later claim). The lock is per
#: competition, not process-wide: a slow pre-deploy in one event must not
#: block the first join in another.
_POOL_LOCKS = {}
_POOL_LOCKS_LOCK = threading.Lock()

#: How many pre-deploy jobs may talk to the portal at once. The portal accepts
#: one provision job at a time, so letting every competition warm in parallel
#: only produces 409s; the rest queue as ``status: "queued"``.
MAX_WARM_JOBS_DEFAULT = 2
_WARM_GATE = None
_WARM_GATE_LOCK = threading.Lock()

_PIN_CACHE = {}
_PIN_CACHE_LOCK = threading.Lock()


def _pool_lock(comp_id: str) -> threading.Lock:
    with _POOL_LOCKS_LOCK:
        lock = _POOL_LOCKS.get(comp_id)
        if lock is None:
            lock = threading.Lock()
            _POOL_LOCKS[comp_id] = lock
        return lock


def max_warm_jobs() -> int:
    """Concurrent pre-deploy cap (env: HUITZILOPOCHTLI_MAX_WARM_JOBS)."""
    try:
        return max(1, int(os.environ.get("HUITZILOPOCHTLI_MAX_WARM_JOBS",
                                         MAX_WARM_JOBS_DEFAULT)))
    except (TypeError, ValueError):
        return MAX_WARM_JOBS_DEFAULT


def _warm_gate() -> threading.BoundedSemaphore:
    """Semaphore sized by the current env value (rebuilt when it changes)."""
    global _WARM_GATE
    size = max_warm_jobs()
    with _WARM_GATE_LOCK:
        if _WARM_GATE is None or _WARM_GATE[0] != size:
            _WARM_GATE = (size, threading.BoundedSemaphore(size))
        return _WARM_GATE[1]


def config() -> tuple:
    """(portal base URL, prebind secret) from the environment."""
    base = os.environ.get("HUITZILOPOCHTLI_WORKSHOP_URL", "").rstrip("/")
    secret = os.environ.get("HUITZILOPOCHTLI_WORKSHOP_SECRET", "")
    return base, secret


def enabled() -> bool:
    return bool(config()[0])


#: How long a run's box stays accessible after the run clock ends, so the
#: player can investigate the hardened state, before the sweeper releases
#: (destroys + frees the seat) it (env: HUITZILOPOCHTLI_POST_RUN_GRACE_S).
POST_RUN_GRACE_DEFAULT = 1800.0


def post_run_grace_s() -> float:
    """Post-run box access window in seconds (default 30 minutes)."""
    try:
        return max(0.0, float(os.environ.get(
            "HUITZILOPOCHTLI_POST_RUN_GRACE_S", POST_RUN_GRACE_DEFAULT)))
    except (TypeError, ValueError):
        return POST_RUN_GRACE_DEFAULT


def public_base() -> str:
    """Origin for back_url when there is no request to derive one from."""
    return os.environ.get("HUITZILOPOCHTLI_PUBLIC_URL", "").rstrip("/")


def _admin_password() -> str:
    return os.environ.get("HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD", "")


def _back_url(comp: CompetitionRecord) -> str:
    base = public_base()
    return f"{base}/c/{comp.slug}/join/success" if base else ""


def ensure_pool(store: Store, comp: CompetitionRecord) -> tuple:
    """Serialize first-claim pool provisioning for one competition.

    Per-competition, not process-wide: two events starting at once must not
    queue behind each other, and each already has its own portal pool.
    """
    with _pool_lock(comp.id):
        return _ensure_pool_locked(store, comp)


def _pin_is_alive(base: str, password: str, pool_code: str,
                  max_age: float = 8.0) -> bool:
    """Does the pinned pool still exist on the portal? (short TTL cache)"""
    now = time.time()
    with _PIN_CACHE_LOCK:
        hit = _PIN_CACHE.get(pool_code)
        if hit is not None and now - hit[0] < max_age:
            return hit[1]
    try:
        alive = workshop.pool_snapshot(base, password, pool_code,
                                       timeout=5.0) is not None
    except workshop.WorkshopError:
        return True  # portal down: let the claim report the real error
    with _PIN_CACHE_LOCK:
        _PIN_CACHE[pool_code] = (now, alive)
    return alive


def _ensure_pool_locked(store: Store, comp: CompetitionRecord) -> tuple:
    """The competition's dedicated workshop pool, provisioned on demand.

    Each competition gets its own pool, cloned from the scenario record's
    ``pool`` block (the ranked template the box was built from) — the engine
    never selects among the portal's pre-existing pools, so a competition can
    never be handed a box of the wrong mode. Existing pins (older
    competitions, or a pool provisioned for this competition before an engine
    restart) are honored, but only while the portal still has the pool: a pin
    left behind by a deleted or failed pool is cleared and re-provisioned
    instead of failing every later claim with "Unknown code.".
    Returns ``(pool_code, error)``; the error is a player-presentable string
    and is also what the sweeper retries on.
    """
    if comp.workshop_pool_code:
        base = config()[0]
        password = _admin_password()
        if not base or not password or _pin_is_alive(
                base, password, comp.workshop_pool_code):
            return comp.workshop_pool_code, None
        store.update_competition(comp.id, workshop_pool_code=None,
                                 workshop_pool_name=None)
        store.add_audit("system", "competition_pool_stale", comp.id,
                        details_json=json.dumps(
                            {"pool": comp.workshop_pool_code}))
        print(f"competition {comp.slug}: pinned pool "
              f"{comp.workshop_pool_code} is gone; provisioning a fresh one",
              flush=True)
        comp = store.get_competition(comp.id)
    spec = scenario_mod.load_pool_spec(store, comp.scenario_name,
                                       comp.scenario_version)
    if not spec:
        return None, ("the scenario has no pool provisioning block; add a "
                      "'pool:' section to the ranked scenario, recompile, and "
                      "re-upload the engine record")
    base = config()[0]
    password = _admin_password()
    if not password:
        return None, "the workshop admin password is not configured"
    name = workshop.competition_pool_name(comp.slug)
    try:
        existing = workshop.find_pool_by_name(workshop.list_pools(base, password), name)
        if existing is not None:
            template = (existing.get("config") or {}).get("template_vm_id")
            if template is not None and template != spec.get("template_vm_id"):
                return None, (f"workshop pool {existing['code']} clones template "
                              f"{template}, not the scenario's "
                              f"{spec.get('template_vm_id')}; remove that pool "
                              "from the portal and retry")
            _pin_pool(store, comp, existing["code"], "reused")
            return existing["code"], None
        result = workshop.provision_pool(base, password, comp.slug, spec)
    except workshop.WorkshopError as exc:
        if "already running" not in str(exc).lower():
            return None, str(exc)
        # Another competition's provisioning job is still holding the
        # portal's single job slot. Wait for it, then reuse our pool if it
        # appeared; a 409 is a transient queue, not a terminal error.
        for _ in range(10):
            time.sleep(1.0)
            try:
                existing = workshop.find_pool_by_name(
                    workshop.list_pools(base, password), name)
            except workshop.WorkshopError:
                existing = None
            if existing is not None:
                template = (existing.get("config") or {}).get("template_vm_id")
                if template is not None and \
                        template != spec.get("template_vm_id"):
                    return None, (f"workshop pool {existing['code']} clones "
                                  f"template {template}, not the scenario's "
                                  f"{spec.get('template_vm_id')}")
                _pin_pool(store, comp, existing["code"], "reused_pending")
                return existing["code"], None
        return None, ("the workshop portal is still provisioning another "
                      "pool; the claim will retry")
    _pin_pool(store, comp, result["pool_code"], "provisioned")
    return result["pool_code"], None


def _pin_pool(store: Store, comp: CompetitionRecord, pool_code: str,
              source: str) -> None:
    pool_name = workshop.competition_pool_name(comp.slug)
    store.update_competition(comp.id, workshop_pool_code=pool_code,
                             workshop_pool_name=pool_name)
    store.add_audit("system", "competition_pool", comp.id,
                    details_json=json.dumps({"pool": pool_code,
                                             "pool_name": pool_name,
                                             "source": source}))
    print(f"competition {comp.slug}: workshop pool {pool_code} "
          f"({pool_name}, {source})", flush=True)


def pool_name_for(comp: Optional[CompetitionRecord]) -> Optional[str]:
    """The portal pool name this competition owns (legacy rows derive it).

    Stored so teardown can match the exact pool, not a slug prefix. Rows
    written before the column existed were always named after the slug, so the
    derived fallback is exact for them.
    """
    if comp is None:
        return None
    return comp.workshop_pool_name or workshop.competition_pool_name(comp.slug)


def _warm_job_update(comp_id: str, **fields) -> None:
    with _WARM_LOCK:
        job = _WARM_JOBS.get(comp_id)
        if job is not None:
            job.update(fields)


def warm_status(comp_id: str) -> dict:
    """The last pre-deploy job for ``comp_id`` ({"status": "idle"} if none)."""
    with _WARM_LOCK:
        job = _WARM_JOBS.get(comp_id)
        return dict(job) if job is not None else {"status": "idle"}


def live_pool_status(comp: CompetitionRecord) -> dict:
    """The competition pool's usable-box counts right now, from the portal.

    Cheap enough for the admin page's poll: one GET per render. Never raises
    -- portal trouble reads as ``{"status": "unavailable"}`` and no pool pin
    (nothing pre-deployed yet) as ``{"status": "unpinned"}``."""
    if not comp.workshop_pool_code:
        return {"status": "unpinned"}
    base, _secret = config()
    password = _admin_password()
    if not base or not password:
        return {"status": "unavailable", "error": "the workshop portal is not configured"}
    try:
        snap = workshop.pool_snapshot(base, password, comp.workshop_pool_code)
    except workshop.WorkshopError as exc:
        return {"status": "unavailable", "error": str(exc)[:200]}
    if snap is None:
        return {"status": "unpinned"}
    return {"status": "ok",
            "available": int(snap.get("available") or 0),
            "total": int(snap.get("total") or 0)}


#: Dashboard pool counts: one portal read for every row, cached briefly.
_POOL_COUNTS_CACHE = {"at": 0.0, "data": {}}


def portal_pool_counts(max_age: float = 10.0) -> dict:
    """portal pool code -> {"available", "total"} for the admin dashboard.

    The console renders every competition on one page; asking the portal once
    (short timeout, short cache) keeps that a single read instead of one per
    row. Portal trouble is an empty map, never a page error.
    """
    now = time.time()
    with _PIN_CACHE_LOCK:
        if now - _POOL_COUNTS_CACHE["at"] < max_age:
            return dict(_POOL_COUNTS_CACHE["data"])
    base, _secret = config()
    password = _admin_password()
    data = {}
    if base and password:
        try:
            pools = workshop.list_pools(base, password, timeout=3.0)
        except workshop.WorkshopError:
            pools = []
        for p in pools:
            if isinstance(p, dict) and p.get("code"):
                data[p["code"]] = {"available": int(p.get("available") or 0),
                                   "total": int(p.get("total") or 0)}
    with _PIN_CACHE_LOCK:
        _POOL_COUNTS_CACHE["at"] = now
        _POOL_COUNTS_CACHE["data"] = data
    return dict(data)


#: Auto-warm: keep a small buffer of unclaimed, available (cloned, booted,
#: past their access-port wait) boxes in each live competition's pool, so the
#: next claim dispenses a preheated box instead of waiting on a cold clone.
#: The portal clones on demand either way; auto-warm only hides that latency.
#: Target is env-tunable (HUITZILOPOCHTLI_AUTOWARM_TARGET, 0 disables);
#: HUITZILOPOCHTLI_AUTOWARM=0 turns the feature off entirely. Topping up is
#: asynchronous on the portal, so its ``available`` count stays low for
#: minutes after a request — a cooldown per competition keeps the sweeper
#: from stacking redundant redeploy jobs against a slow provisioning run.
AUTOWARM_TARGET_DEFAULT = 2
AUTOWARM_COOLDOWN_S = 120.0

_AUTOWARM_LAST_LOCK = threading.Lock()
_AUTOWARM_LAST: dict = {}  # comp id -> last top-up attempt time


def autowarm_target() -> int:
    """Unclaimed-buffer size the engine keeps warm (env-tunable; 0 = off)."""
    try:
        return max(0, int(os.environ.get("HUITZILOPOCHTLI_AUTOWARM_TARGET",
                                         AUTOWARM_TARGET_DEFAULT)))
    except (TypeError, ValueError):
        return AUTOWARM_TARGET_DEFAULT


def autowarm_enabled() -> bool:
    raw = os.environ.get("HUITZILOPOCHTLI_AUTOWARM", "1").strip().lower()
    return raw not in ("0", "false", "no", "off")


def autowarm_tick(store: Store, comp: CompetitionRecord, *,
                  now: Optional[float] = None, stats: Optional[dict] = None,
                  force: bool = False) -> int:
    """Top the competition's pool back up to the auto-warm buffer.

    Runs from the claim sweep (every sweep interval, ~15 s) and after each
    successful claim. Reads the pinned pool's snapshot; if fewer boxes are
    available than the target, asks the portal for the deficit. Never raises:
    a portal blip is logged and left to the next tick. Returns the requested
    count (0 when nothing was asked for). A dead pin is left to the claim
    path's own recovery logic — auto-warm never provisions a fresh pool.
    """
    target = autowarm_target()
    if not autowarm_enabled() or target < 1 or comp.status != "live":
        return 0
    base, _secret = config()
    password = _admin_password()
    pool_code = comp.workshop_pool_code
    if not (base and password and pool_code):
        return 0
    now = time.time() if now is None else now
    with _AUTOWARM_LAST_LOCK:
        if not force and now - _AUTOWARM_LAST.get(comp.id, 0.0) \
                < AUTOWARM_COOLDOWN_S:
            return 0
        _AUTOWARM_LAST[comp.id] = now
    try:
        snap = workshop.pool_snapshot(base, password, pool_code)
        if snap is None:
            return 0
        deficit = target - int(snap.get("available") or 0)
        if deficit > 0:
            workshop.provision_more(base, password, pool_code, deficit)
    except workshop.WorkshopError as exc:
        print(f"competition {comp.slug}: auto-warm failed: {exc}", flush=True)
        return 0
    if deficit > 0:
        store.add_audit("system", "competition_autowarm", comp.id,
                        details_json=json.dumps({"deficit": deficit,
                                                 "target": target}))
        if stats is not None:
            stats["autowarmed"] = stats.get("autowarmed", 0) + 1
    return deficit


#: Standing reasons a competition has nothing to pre-deploy from, phrased for#: the admin page. Each names the knob to touch and carries no secret. The
#: dashboard shows them before the click (and the click is refused) so a
#: scenario nobody gave a pool to does not look like a broken button: the
#: failure used to arrive seconds later as a background job note, after the
#: operator had already pressed it.
PORTAL_MISSING = ("The workshop portal is not configured "
                  "(HUITZILOPOCHTLI_WORKSHOP_URL), so there is nowhere to "
                  "pre-deploy boxes to.")
PORTAL_PASSWORD_MISSING = (
    "The workshop portal admin password "
    "(HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD) is not set, so the engine "
    "cannot ask the portal to clone boxes.")

#: The short form for the admin console's competition rows.
POOL_SOURCE_MISSING_SHORT = "No pool to pre-deploy from"


def no_pool_message(scenario_name: str) -> str:
    """Why this scenario can clone nothing, and how to fix it."""
    return (f"No pool to pre-deploy from: the scenario '{scenario_name}' "
            "carries no pool block, so the engine has no ranked template to "
            "clone. Add a 'pool:' section to the ranked scenario (or an entry "
            "for it in the engine's pools file), recompile and re-upload the "
            "scenario, then reload this page.")


def predeploy_blocker(store: Store, comp: CompetitionRecord, *,
                      pool: Optional[dict] = None,
                      check_pin: bool = True) -> Optional[str]:
    """Why there is no pool to pre-deploy from right now, or ``None``.

    Pre-deploy warms the pool pinned to the competition; with no pin — or a
    pin the portal no longer recognises — that pool has to be cloned from the
    scenario record's ``pool:`` block. When neither exists, the only thing a
    click can produce is a failed job, so the dashboard says so up front.

    ``pool`` lets a caller that already took a live snapshot
    (``live_pool_status``) hand it over instead of reading the portal twice;
    ``check_pin=False`` skips the portal read entirely, which is what the
    competition rows want (a cheap structural answer, on a 30 s poll). A
    portal that is merely unreachable never reads as blocked — the claim and
    warm paths report the real transport error.
    """
    base, _secret = config()
    if not base:
        return PORTAL_MISSING
    password = _admin_password()
    if not password:
        return PORTAL_PASSWORD_MISSING
    if comp.workshop_pool_code:
        if not check_pin:
            # Structural only: a pin may be topping up a pool that is still
            # alive, and telling needs a portal read the row must not make.
            # The competition page (which has the snapshot) decides.
            return None
        if pool is not None:
            gone = pool.get("status") == "unpinned"
        else:
            gone = not _pin_is_alive(base, password, comp.workshop_pool_code)
        if not gone:
            # The pool is there; topping it up needs no scenario pool block.
            return None
        # The pin is dead, but the scenario can still clone a fresh pool:
        # warm_boxes recovers that itself, so it is not a blocker.
    if not scenario_mod.load_pool_spec(store, comp.scenario_name,
                                       comp.scenario_version):
        return no_pool_message(comp.scenario_name)
    return None


def start_warm(store: Store, comp: CompetitionRecord, count) -> dict:
    """Start pre-deploying ``count`` boxes into the competition's pool.

    Returns the job state immediately; the work runs in a daemon thread so
    the admin page is not held open for the several minutes a cold batch
    takes. One job per competition at a time (a second click joins the
    running job instead of asking the portal for another batch). A click that
    cannot possibly work is refused here rather than handed to the thread, so
    the operator gets the reason on the spot instead of as a job note.
    """
    try:
        count = int(count)
    except (TypeError, ValueError):
        return {"status": "error", "error": "Box count must be a number."}
    if count < 1 or count > WARM_MAX:
        return {"status": "error",
                "error": f"Box count must be between 1 and {WARM_MAX}."}
    with _WARM_LOCK:
        _prune_warm_jobs_locked()
        existing = _WARM_JOBS.get(comp.id)
        if existing is not None and existing.get("status") in ("running",
                                                               "queued"):
            return dict(existing)
    # Outside the lock: the blocker may read the portal, and the worker takes
    # the same lock for its progress updates. The registration below re-checks
    # for a running job, so two simultaneous clicks still start only one batch.
    blocker = predeploy_blocker(store, comp)
    if blocker:
        store.add_audit("system", "competition_warm_blocked", comp.id,
                        details_json=json.dumps(
                            {"requested": count, "reason": blocker[:300]}))
        return {"status": "error", "requested": count, "blocked": True,
                "error": blocker}
    with _WARM_LOCK:
        _prune_warm_jobs_locked()
        existing = _WARM_JOBS.get(comp.id)
        if existing is not None and existing.get("status") in ("running",
                                                               "queued"):
            return dict(existing)
        job = {
            "status": "queued", "requested": count,
            "pool_code": comp.workshop_pool_code,
            "available": 0, "total": 0, "in_use": 0,
            "started_at": time.time(), "finished_at": None, "error": None,
        }
        _WARM_JOBS[comp.id] = job
    threading.Thread(target=_warm_worker, name=f"warm-{comp.slug}",
                     args=(store, comp.id, count), daemon=True).start()
    return dict(job)


def _prune_warm_jobs_locked(max_age: float = 3600.0) -> None:
    """Drop finished job records older than ``max_age`` (caller holds the lock)."""
    now = time.time()
    for cid, job in list(_WARM_JOBS.items()):
        if job.get("status") in ("running", "queued"):
            continue
        done = job.get("finished_at") or job.get("started_at") or 0
        if now - float(done) > max_age:
            _WARM_JOBS.pop(cid, None)


def _warm_worker(store: Store, comp_id: str, count: int) -> None:
    gate = _warm_gate()
    gate.acquire()
    try:
        _warm_job_update(comp_id, status="running", started_at=time.time())
        comp = store.get_competition(comp_id)
        if comp is None:
            raise RuntimeError("competition disappeared before pre-deploy")
        result = warm_boxes(store, comp, count)
        result["finished_at"] = time.time()
        _warm_job_update(comp_id, **result)
    except Exception as exc:  # never kill the process for a warm-up failure
        _warm_job_update(comp_id, status="error", error=str(exc)[:300],
                         finished_at=time.time())
        print(f"competition {comp_id}: pre-deploy failed: {exc}", flush=True)
    finally:
        gate.release()


def warm_boxes(store: Store, comp: CompetitionRecord, count: int, *,
               wait_s: Optional[float] = None) -> dict:
    """Synchronously fill the competition's pool with ``count`` usable boxes.

    A competition with no pinned pool gets one created with the requested
    size; an already-pinned pool is topped up through the portal's redeploy
    endpoint. Polls the portal until that many boxes are *available* (cloned,
    booted and past their access-port wait) or the deadline passes. Never
    raises for portal trouble -- the returned dict carries ``status``
    (``ready`` | ``timeout`` | ``error``) and the caller audits it.
    """
    try:
        count = int(count)
    except (TypeError, ValueError):
        return {"status": "error", "error": "Box count must be a number.",
                "requested": count}
    if count < 1 or count > WARM_MAX:
        return {"status": "error",
                "error": f"Box count must be between 1 and {WARM_MAX}.",
                "requested": count}
    base, _secret = config()
    password = _admin_password()
    if not base:
        return {"status": "error", "requested": count,
                "error": "the workshop portal is not configured"}
    if not password:
        return {"status": "error", "requested": count,
                "error": "the workshop admin password is not configured"}
    pool_code = comp.workshop_pool_code
    created = False
    if pool_code and not _pin_is_alive(base, password, pool_code):
        # The pin outlived its pool (an operator delete, a portal reset).
        # Topping up a pool that is gone can only fail, and the scenario can
        # still clone a fresh one from its own template, so recover the same
        # way a first claim does instead of reporting a dead end.
        store.update_competition(comp.id, workshop_pool_code=None,
                                 workshop_pool_name=None)
        store.add_audit("system", "competition_pool_stale", comp.id,
                        details_json=json.dumps({"pool": pool_code}))
        print(f"competition {comp.slug}: pinned pool {pool_code} is gone; "
              "pre-deploy will clone a fresh one", flush=True)
        comp = store.get_competition(comp.id) or comp
        pool_code = None
    if not pool_code:
        with _pool_lock(comp.id):
            # Re-read under the lock: a claim or another warm call may have
            # provisioned the pool while this one was waiting.
            fresh = store.get_competition(comp.id)
            comp = fresh or comp
            pool_code = comp.workshop_pool_code
            if not pool_code:
                spec = scenario_mod.load_pool_spec(store, comp.scenario_name,
                                                   comp.scenario_version)
                if not spec:
                    return {"status": "error", "requested": count,
                            "error": ("the scenario has no pool provisioning "
                                      "block; add a 'pool:' section and "
                                      "re-upload it")}
                spec = dict(spec)
                spec["vm_count"] = max(count, int(spec.get("vm_count") or 2))
                pool_code = None
                for attempt in range(31):
                    try:
                        result = workshop.provision_pool(base, password,
                                                         comp.slug, spec)
                    except workshop.WorkshopError as exc:
                        if "already running" not in str(exc).lower() \
                                or attempt == 30:
                            return {"status": "error", "requested": count,
                                    "error": str(exc)}
                        # The portal allows one provision job at a time (the
                        # other competition may be filling its pool). Wait for
                        # it, then retry -- warming must be reliable, not
                        # another source of 409s.
                        time.sleep(10)
                        try:
                            existing = workshop.find_pool_by_name(
                                workshop.list_pools(base, password),
                                workshop.competition_pool_name(comp.slug))
                        except workshop.WorkshopError:
                            existing = None
                        if existing is not None:
                            pool_code = existing["code"]
                            _pin_pool(store, comp, pool_code, "reused_warm")
                            break
                        continue
                    pool_code = result["pool_code"]
                    _pin_pool(store, comp, pool_code, "provisioned_warm")
                    created = True
                    break
                if not pool_code:
                    return {"status": "error", "requested": count,
                            "error": "the portal never accepted the pool"}
    started = time.time()
    deadline = started + (WARM_WAIT_S if wait_s is None else max(1.0, wait_s))
    topup_sent = created
    next_topup_at = 0.0
    available = total = in_use = 0
    target = None
    while True:
        try:
            snap = workshop.pool_snapshot(base, password, pool_code)
        except workshop.WorkshopError as exc:
            return {"status": "error", "requested": count, "pool_code": pool_code,
                    "available": available, "total": total, "in_use": in_use,
                    "error": str(exc)}
        if snap is None:
            return {"status": "error", "requested": count, "pool_code": pool_code,
                    "available": available, "total": total, "in_use": in_use,
                    "error": "the portal no longer lists the competition's pool"}
        available = int(snap.get("available") or 0)
        total = int(snap.get("total") or 0)
        in_use = int(snap.get("in_use") or 0)
        if target is None:
            # The requested count ADDS to whatever the pool already has ready
            # (a fresh pool starts at zero), so pre-deploying 2 into a pool
            # holding 12 grows it to 14 instead of being satisfied instantly
            # by the boxes already in it.
            target = count if created else available + count
        _warm_job_update(comp.id, pool_code=pool_code, available=available,
                         total=total, in_use=in_use, target=target)
        if available >= target:
            return {"status": "ready", "requested": count, "pool_code": pool_code,
                    "available": available, "total": total, "in_use": in_use,
                    "target": target,
                    "waited_s": round(time.time() - started, 1)}
        now = time.time()
        if now >= deadline:
            return {"status": "timeout", "requested": count,
                    "pool_code": pool_code, "available": available,
                    "total": total, "in_use": in_use, "target": target,
                    "waited_s": round(now - started, 1),
                    "error": (f"only {available} of {target} boxes were ready "
                              f"after {int(now - started)} s")}
        # A brand-new pool is already provisioning `count` boxes. An existing
        # pool is topped up once toward the additive target; a 409 means an
        # earlier portal job is still running, so retry after it has had time
        # to finish.
        if not topup_sent and now >= next_topup_at:
            try:
                workshop.provision_more(base, password, pool_code,
                                        max(0, target - available))
                topup_sent = True
            except workshop.WorkshopError as exc:
                if "already running" in str(exc).lower():
                    next_topup_at = now + 15.0
                else:
                    return {"status": "error", "requested": count,
                            "pool_code": pool_code, "available": available,
                            "total": total, "in_use": in_use,
                            "error": str(exc)}
        time.sleep(3.0)


def _pool_vmids(base: str, password: str, pool_name: str, pool_code: str,
                expected: int, attempts: Optional[int] = None) -> list:
    """VMIDs the portal lists for exactly this competition's pool.

    Pre-provisioned clones register asynchronously, so an operator who ends a
    competition immediately after its first claim can race the portal. When
    the pool reports a non-zero size, poll briefly before concluding there is
    nothing to destroy. ``attempts`` overrides that decision for the
    pool-config-already-gone case, where the expected count is unknown.

    The match is the pool code, or the portal's ``<pool name>-<n>`` student id
    **anchored on the full pool name**. A bare ``startswith`` used to make
    competition ``demo`` destroy ``demo-2``'s clones at End -- exactly what
    End followed by Rerun creates.
    """
    student_re = re.compile(re.escape(pool_name) + r"-\d+\Z") if pool_name else None
    tries = attempts if attempts is not None else (5 if expected else 1)
    for attempt in range(tries):
        vms = workshop.list_vms(base, password)
        vmids = []
        for v in vms:
            if not isinstance(v, dict):
                continue
            student = str(v.get("student_id") or "")
            if v.get("pool") == pool_code or (
                    student_re is not None and student_re.match(student)):
                vmids.append(v.get("vmid"))
        if vmids:
            return vmids
        if attempt + 1 < tries:
            time.sleep(2.0)
    return []


def extend_pool_expiry(store: Store, comp: CompetitionRecord,
                       extension_s: int, *, margin_s: float = 300.0) -> dict:
    """Bump the portal's reclaim clock when overtime would outlive it.

    The portal reclaims claimed VMs on its own ``expires_at`` (the engine
    keeps a copy as the player's ``claim_expires_at``); an extension that
    pushes a run's ``ends_at`` within ``margin_s`` of that instant means the
    box could be torn down mid-overtime. The portal's admin listing identifies
    clones by VMID but not by engine player, so the bump is coarse: every
    clone in this competition's pool gets the same bump. Portal TTLs already
    exceed typical academy run lengths, so for common short extensions this
    is a no-op -- it only wakes up for long runs or long extensions.
    """
    base, _secret = config()
    password = _admin_password()
    if not (base and password and comp.workshop_pool_code):
        return {"bumped": False,
                "reason": "portal not configured or no pinned pool"}
    tight = [p for p in store.list_players(comp.id)
             if p.box_id and p.ends_at is not None
             and p.claim_expires_at is not None
             and p.ends_at + margin_s > p.claim_expires_at]
    if not tight:
        return {"bumped": False, "reason": "portal reclaim clocks have headroom"}
    hours = max(1, -(-int(extension_s) // 3600))
    # The name goes in WITHOUT a trailing dash: _pool_vmids anchors
    # ``<pool name>-<n>`` itself, and a dash here would never match.
    pool_name = workshop.competition_pool_name(comp.slug)
    expected = int(getattr(store.get_competition(comp.id),
                           "max_players", 0) or 0) or len(tight)
    vmids = _pool_vmids(base, password, pool_name, comp.workshop_pool_code,
                        expected, attempts=2)
    if not vmids:
        return {"bumped": False,
                "reason": "no portal VMs found for the pool",
                "needed_by": [p.display_name for p in tight]}
    outcomes = workshop.extend_vms(base, password, vmids, hours)
    return {"bumped": True, "hours": hours, "outcomes": outcomes}


def cleanup_pool(store: Store, comp: Optional[CompetitionRecord]) -> dict:
    """Release a competition's VMs and drop its pool once the run is over.

    Only pools this engine provisioned (name ``huitz-ranked-<slug>``) are
    released and deleted; a competition pinned to a pre-existing shared pool
    just has its pin cleared so the operator's pool stays untouched. Best
    effort and idempotent — the sweeper retries while the pin survives.

    The pool config can be gone while clones still live (a crash between
    provision and pin, an operator delete, or the mid-run engine restart that
    produced this round's leak). In that case we still enumerate the portal's
    VM list by pool code/student_id and destroy the clones; a missing config
    is never treated as "nothing to clean".
    """
    stats = {"released": 0, "destroyed": 0, "deleted": False,
             "legacy": False, "pool_missing": False,
             "destroy_pending": False}
    if comp is None or not comp.workshop_pool_code:
        return stats
    base, _secret = config()
    password = _admin_password()
    pinned = comp.workshop_pool_code
    if base and password:
        try:
            pools = workshop.list_pools(base, password)
        except workshop.WorkshopError:
            return stats  # portal unreachable; the sweeper retries
        entry = next((p for p in pools if isinstance(p, dict)
                      and p.get("code") == pinned), None)
        owned_name = pool_name_for(comp)
        if entry is not None and entry.get("name") != owned_name:
            stats["legacy"] = True
            store.update_competition(comp.id, workshop_pool_code=None,
                                     workshop_pool_name=None)
            store.add_audit("system", "competition_pool_cleanup", comp.id,
                            details_json=json.dumps({"pool": pinned, **stats}))
            return stats
        # Release claimed players, then destroy every clone that belongs to
        # this competition. Both happen whether or not the config still exists.
        for p in store.list_players(comp.id):
            if p.claim_uid:
                try:
                    workshop.release_vm(base, p.claim_uid)
                    stats["released"] += 1
                except workshop.WorkshopError:
                    pass  # the portal expires it; do not block cleanup
        expected = int((entry or {}).get("count")
                       or (entry or {}).get("total") or 0)
        try:
            vmids = _pool_vmids(base, password, owned_name, pinned, expected,
                                attempts=None if entry is not None else 3)
        except workshop.WorkshopError:
            return stats  # keep the pin; the sweeper retries
        if vmids:
            try:
                job = workshop.destroy_vms(base, password, vmids)
            except workshop.WorkshopError:
                return stats  # keep the pin; the sweeper retries
            if job.get("status") == "error":
                return stats
            stats["destroyed"] += len(vmids)
            if job.get("status") != "done":
                stats["destroy_pending"] = True
                # Keep the pin: the destroy job is still running, and the
                # next sweep must verify the clones are actually gone.
                print(f"competition {comp.slug}: pool {pinned} destroy "
                      f"pending {stats}", flush=True)
                return stats
        if entry is not None:
            try:
                workshop.delete_pool(base, password, pinned)
                stats["deleted"] = True
            except workshop.WorkshopError:
                return stats  # keep the pin; the sweeper retries
        else:
            stats["pool_missing"] = True
            # No config left to delete; the clones (if any) were swept above.
        # Deleting the config can race a clone registering itself. Sweep once
        # more now that the pool is gone; the portal keeps the VM entry (and
        # its pool code) even without a saved config.
        try:
            late = _pool_vmids(base, password, owned_name, pinned, expected=0,
                               attempts=1)
        except workshop.WorkshopError:
            late = []
        if late:
            try:
                job = workshop.destroy_vms(base, password, late)
            except workshop.WorkshopError:
                return stats
            if job.get("status") == "error":
                return stats
            stats["destroyed"] += len(late)
            if job.get("status") != "done":
                stats["destroy_pending"] = True
                print(f"competition {comp.slug}: pool {pinned} late destroy "
                      f"pending {stats}", flush=True)
                return stats
    store.update_competition(comp.id, workshop_pool_code=None,
                             workshop_pool_name=None)
    store.add_audit("system", "competition_pool_cleanup", comp.id,
                    details_json=json.dumps({"pool": pinned, **stats}))
    print(f"competition {comp.slug}: pool {pinned} cleaned up {stats}",
          flush=True)
    return stats


def player_csrf(server_secret: bytes, player_id: str) -> str:
    return hmac.new(server_secret, b"claim:" + player_id.encode("utf-8"),
                    hashlib.sha256).hexdigest()


def check_csrf(server_secret: bytes, player_id: str, token) -> bool:
    return bool(token) and hmac.compare_digest(
        player_csrf(server_secret, player_id), str(token))


def _record_error(store: Store, player: PlayerRecord, message) -> None:
    text = (str(message) or "claim failed").strip()[:500]
    store.update_player(
        player.player_id, claim_error=text,
        claim_attempts=(player.claim_attempts or 0) + 1,
        claim_last_attempt_at=time.time())


def _apply_ready(store: Store, player: PlayerRecord, result: dict) -> None:
    store.update_player(
        player.player_id,
        claim_url=result.get("open_url") or result.get("url"),
        claim_uid=result.get("uid"),
        claim_ticket=None,
        claim_expires_at=result.get("expires_at"),
        claim_error=None,
        claim_attempts=(player.claim_attempts or 0) + 1,
        claim_last_attempt_at=time.time())
    # Auto-warm: a box just left the unclaimed buffer, so ask (in the
    # background, best effort) for a replacement rather than waiting for the
    # next sweep tick. The per-competition cooldown keeps a rapid run of
    # claims from stacking redeploy jobs; the sweep fills any remainder.
    threading.Thread(target=autowarm_thread_entry, name="autowarm-fire",
                     args=(store, player.competition_id),
                     daemon=True).start()


def autowarm_thread_entry(store: Store, competition_id: str) -> None:
    comp = store.get_competition(competition_id)
    if comp is not None:
        autowarm_tick(store, comp)


def start(store: Store, comp: CompetitionRecord, player: PlayerRecord,
          *, back_url: str = "") -> dict:
    """Claim a VM for an invited player. Best effort, stores the outcome."""
    if player.box_id:
        return {"ok": True, "bound": True}
    if player.claim_url:
        return {"ok": True, "url": player.claim_url}
    if player.claim_ticket:
        return {"ok": True, "pending": True}
    base, secret = config()
    if not base:
        _record_error(store, player, "the workshop portal is not configured")
        return {"ok": False, "error": "the workshop portal is not configured"}
    # Pools are picked automatically; resolve lazily so a competition created
    # while the portal was down still dispenses on the first join.
    pool, pool_err = ensure_pool(store, comp)
    if not pool:
        message = pool_err or "no workshop pool is available"
        _record_error(store, player, message)
        return {"ok": False, "error": message}
    try:
        result = workshop.claim_vm(
            base, pool, code=player.join_code_plain or None,
            secret=secret or None, back_url=back_url, timeout=45.0)
    except workshop.WorkshopError as exc:
        # A pool can disappear between the pin check and the claim (the
        # portal's config file is not transactional with our pin). Treat the
        # portal's "Unknown code." as a stale pin: clear it, provision a fresh
        # pool, and retry once instead of leaving the player failing forever.
        if (comp.workshop_pool_code
                and "unknown code" in str(exc).lower()):
            store.update_competition(comp.id, workshop_pool_code=None,
                                     workshop_pool_name=None)
            store.add_audit("system", "competition_pool_stale", comp.id,
                            player.player_id,
                            details_json=json.dumps(
                                {"pool": comp.workshop_pool_code,
                                 "error": str(exc)[:200]}))
            print(f"competition {comp.slug}: claim hit a stale pool "
                  f"{comp.workshop_pool_code}; reprovisioning", flush=True)
            fresh = store.get_competition(comp.id)
            pool, pool_err = ensure_pool(store, fresh)
            if not pool:
                message = pool_err or "no workshop pool is available"
                _record_error(store, player, message)
                return {"ok": False, "error": message}
            try:
                result = workshop.claim_vm(
                    base, pool, code=player.join_code_plain or None,
                    secret=secret or None, back_url=back_url, timeout=45.0)
            except workshop.WorkshopError as exc2:
                _record_error(store, player, exc2)
                return {"ok": False, "error": str(exc2)}
        # The portal may not have the prebind secret yet. A plain claim still
        # gets the player a VM, so fall back to the manual join rather than
        # leaving them with nothing. This used to be silent, which meant an
        # operator who configured HUITZILOPOCHTLI_WORKSHOP_SECRET never
        # learned the advertised no-typing join was off (round 6 finding 6).
        elif secret and "prebind" in str(exc).lower():
            store.add_audit("system", "prebind_unavailable", comp.id,
                            player.player_id,
                            details_json=json.dumps({"error": str(exc)[:200]}))
            print(f"competition {comp.slug}: portal prebind unavailable "
                  f"({exc}); players must enter their join code by hand",
                  flush=True)
            try:
                result = workshop.claim_vm(base, pool, timeout=30.0)
            except workshop.WorkshopError as exc2:
                _record_error(store, player, exc2)
                return {"ok": False, "error": str(exc2)}
        else:
            _record_error(store, player, exc)
            return {"ok": False, "error": str(exc)}
    if result.get("open_url") or result.get("url"):
        _apply_ready(store, player, result)
        return {"ok": True, "url": result.get("open_url") or result.get("url")}
    if result.get("ticket"):
        store.update_player(
            player.player_id, claim_ticket=result["ticket"],
            claim_url=None, claim_error=None,
            claim_attempts=(player.claim_attempts or 0) + 1,
            claim_last_attempt_at=time.time())
        return {"ok": True, "pending": True, "stage": result.get("stage")}
    _record_error(store, player, "the workshop portal returned no VM")
    return {"ok": False, "error": "the workshop portal returned no VM"}


def poll(store: Store, player: PlayerRecord, *, now: Optional[float] = None,
         force: bool = False) -> PlayerRecord:
    """Advance a provisioning ticket, with per-player throttling and backoff.

    Tickets are polled from the engine on behalf of every open join page, and
    the portal rate-limits redeem calls -- so never poll more than once per
    backoff window (which grows on consecutive failures)."""
    now = time.time() if now is None else now
    if player.box_id or player.claim_url or not player.claim_ticket:
        return player
    base, secret = config()
    if not base:
        return player
    tries = max(1, player.claim_attempts or 1)
    backoff = min(POLL_MIN_INTERVAL * (2 ** (tries - 1)), MAX_POLL_BACKOFF)
    if not force and now - (player.claim_last_poll_at or 0) < backoff:
        return player
    store.update_player(player.player_id, claim_last_poll_at=now)
    try:
        result = workshop.poll_ticket(base, player.claim_ticket,
                                      secret=secret or None)
    except workshop.WorkshopError as exc:
        _record_error(store, player, exc)
        return store.get_player(player.player_id)
    status = result.get("status")
    if status == "ready" and (result.get("open_url") or result.get("url")):
        _apply_ready(store, player, result)
    elif status in ("error", "expired"):
        _record_error(store, player, result.get("detail") or "provisioning failed")
        store.update_player(player.player_id, claim_ticket=None)
    return store.get_player(player.player_id)


def mint_join_code(store: Store, player: PlayerRecord, server_secret: bytes,
                   expires_at: float) -> str:
    """Assign a fresh unique join code to ``player``; returns the plain code.

    The store enforces a unique index on ``join_code_hash`` (a code resolving
    to two players across concurrent competitions would bind a box to the
    wrong run), so a collision is retried here rather than surfacing as a
    failed assignment.
    """
    for _ in range(5):
        code = competition.generate_join_code()
        try:
            store.update_player(
                player.player_id,
                join_code_hash=competition.hash_join_code(server_secret, code),
                join_code_plain=code,
                join_code_expires_at=expires_at)
            return code
        except JoinCodeCollision:
            continue
    raise RuntimeError("could not mint a unique join code")


def rotate_code_if_needed(store: Store, player: PlayerRecord,
                          server_secret: bytes, *, back_url: str = "",
                          now: Optional[float] = None) -> bool:
    """Hand the portal a fresh join code when the old one is about to expire.

    Only the portal uses this code (the player opens a link, not a code), so
    rotation is invisible. Returns True when a new code was pushed."""
    if player.box_id or not player.claim_url or not player.claim_uid:
        return False
    now = time.time() if now is None else now
    if (player.join_code_plain and player.join_code_expires_at
            and player.join_code_expires_at - now > CODE_REFRESH_MARGIN):
        return False
    base, secret = config()
    if not base or not secret:
        return False
    old = (player.join_code_hash, player.join_code_plain,
           player.join_code_expires_at)
    try:
        code = mint_join_code(store, player, server_secret, now + CODE_TTL_S)
    except RuntimeError as exc:
        # Five collisions in a row is practically impossible; if it happens,
        # the page must still render and the sweeper retries later.
        _record_error(store, player, str(exc))
        return False
    try:
        workshop.push_prebind(base, player.claim_uid, code, secret=secret,
                              back_url=back_url)
    except workshop.WorkshopError as exc:
        if getattr(exc, "status", None) in (404, 405):
            # This portal has no /api/prebind: it hands out a VM but never
            # stores a code. The player still types the code by hand, so keep
            # the fresh one (the old one may already be expired) and stop
            # surfacing a portal-shape mismatch as a player-facing error.
            store.add_audit(
                "system", "prebind_unavailable", player.competition_id,
                player.player_id,
                details_json=json.dumps({"error": str(exc)[:200]}))
            store.update_player(player.player_id, claim_error=None)
            return True
        # A real portal outage: keep the code the player may already have.
        try:
            store.update_player(
                player.player_id, join_code_hash=old[0],
                join_code_plain=old[1], join_code_expires_at=old[2])
        except JoinCodeCollision:
            # Another slot took the old code while this one held the new one;
            # the fresh code is still the better answer for this player.
            pass
        _record_error(store, player, f"could not update the VM's join code: {exc}")
        return False
    return True


def _retry_backoff(attempts) -> float:
    tries = max(1, attempts or 1)
    return min(RETRY_MIN_INTERVAL * (2 ** (tries - 1)), MAX_RETRY_BACKOFF)


def _refresh_expired_code(store: Store, server_secret: bytes,
                          player: PlayerRecord, now: float) -> None:
    """Mint a fresh one-time code when the slot's code has expired, so a
    late-dispensed VM still joins itself on first open."""
    if player.join_code_plain and (player.join_code_expires_at or 0) > now + 60:
        return
    mint_join_code(store, player, server_secret, now + CODE_TTL_S)


#: comp id -> (retry_after, consecutive_failures) for the sweeper. A portal
#: error in one competition must not starve the others, so the failing one is
#: backed off instead of being retried on every tick (and instead of the whole
#: loop being skipped).
_SWEEP_BACKOFF = {}
_SWEEP_BACKOFF_LOCK = threading.Lock()
SWEEP_MAX_BACKOFF_S = 600.0
SWEEP_BASE_BACKOFF_S = 30.0
#: Players processed per competition per tick, rotated across ticks so a huge
#: roster cannot monopolize one sweep.
SWEEP_PLAYERS_PER_TICK = 200
_SWEEP_CURSOR = {}


def _sweep_deferred(comp_id: str, now: float) -> bool:
    with _SWEEP_BACKOFF_LOCK:
        retry_at = _SWEEP_BACKOFF.get(comp_id, (0.0, 0))[0]
    return now < retry_at


def _sweep_failed(comp_id: str, exc: Exception) -> None:
    with _SWEEP_BACKOFF_LOCK:
        _failures = _SWEEP_BACKOFF.get(comp_id, (0.0, 0))[1] + 1
        delay = min(SWEEP_BASE_BACKOFF_S * (2 ** (_failures - 1)),
                    SWEEP_MAX_BACKOFF_S)
        _SWEEP_BACKOFF[comp_id] = (time.time() + delay, _failures)
    print(f"competition {comp_id}: sweep error ({exc}); retrying in "
          f"{int(delay)}s", flush=True)


def _sweep_ok(comp_id: str) -> None:
    with _SWEEP_BACKOFF_LOCK:
        _SWEEP_BACKOFF.pop(comp_id, None)


def _sweep_players(comp_id: str, players: list) -> list:
    """A rotating window of ``SWEEP_PLAYERS_PER_TICK`` players for this comp."""
    if len(players) <= SWEEP_PLAYERS_PER_TICK:
        _SWEEP_CURSOR.pop(comp_id, None)
        return players
    start = _SWEEP_CURSOR.get(comp_id, 0) % len(players)
    window = players[start:start + SWEEP_PLAYERS_PER_TICK]
    if len(window) < SWEEP_PLAYERS_PER_TICK:
        window += players[:SWEEP_PLAYERS_PER_TICK - len(window)]
    _SWEEP_CURSOR[comp_id] = (start + len(window)) % len(players)
    return window


def _sweep_one(store: Store, comp: CompetitionRecord, server_secret: bytes,
               now: float, stats: dict) -> None:
    if comp.status == "ended" and comp.workshop_pool_code:
        # A pool outlives its competition only until the next sweep.
        cleanup_pool(store, comp)
        stats["cleaned"] += 1
        return
    if comp.status != "live":
        return
    back = _back_url(comp)
    for p in _sweep_players(comp.id, store.list_players(comp.id)):
        if p.status != "invited" or p.box_id:
            continue
        if p.claim_url:
            if rotate_code_if_needed(store, p, server_secret,
                                     back_url=back, now=now):
                stats["rotated"] += 1
            continue
        if p.claim_ticket:
            poll(store, p, now=now)
            stats["polled"] += 1
            continue
        if now - (p.claim_last_attempt_at or 0) < _retry_backoff(p.claim_attempts):
            continue
        _refresh_expired_code(store, server_secret, p, now)
        fresh = store.get_player(p.player_id)
        out = start(store, comp, fresh, back_url=back)
        if out.get("ok"):
            stats["retried"] += 1
    # Auto-warm: refill the pool's unclaimed buffer (self-cooled; see
    # autowarm_tick). After the player work so a claim this tick just won
    # counts against the snapshot.
    autowarm_tick(store, comp, now=now, stats=stats)
    # Post-run access windows: once a run's clock ends (score frozen — the
    # governing receipt time is ``finished_at`` when a check-in confirmed it,
    # else ``ends_at``), the box stays up ``post_run_grace_s`` so the player
    # can investigate, then the sweeper releases it: destroy via the portal,
    # seat freed for the next claim. The wall the player sees comes from the
    # finishing check-in's directive (engine.checkin); a never-confirmed
    # expiry releases on the same schedule — the clock is the truth. If the
    # competition is ended before a window closes, the End path's pool teardown
    # releases everything at once instead.
    base, _secret = config()
    release_grace = post_run_grace_s()
    if base:
        for p in store.list_players(comp.id):
            if not (p.box_id and p.claim_uid) or p.box_released_at:
                continue
            run_end = max(p.finished_at or 0.0, p.ends_at or 0.0)
            if not run_end or now < run_end + release_grace:
                continue
            try:
                workshop.release_vm(base, p.claim_uid)
            except workshop.WorkshopError:
                stats["release_errors"] += 1
                continue  # best effort; the next sweep retries
            store.release_player_box(p.player_id, now)
            store.add_audit("system", "player_box_released", comp.id,
                            p.player_id,
                            details_json=json.dumps(
                                {"grace_s": release_grace, "ended_at": run_end,
                                 "uid": p.claim_uid}))
            stats["released_boxes"] += 1
    # Auto-release (opt-in per competition): joins closed, every run terminal
    # for a grace period -> end it here so its pool is torn down by the next
    # sweep instead of pinning VMs until an operator notices.
    if comp.auto_end and not comp.join_open:
        players = store.list_players(comp.id)
        terminal = all(p.status in ("finished", "disqualified", "removed")
                       for p in players)
        last_end = max((p.finished_at or p.ends_at or 0) for p in players) \
            if players else (comp.started_at or 0)
        # Option-in grace must not cut a post-run access window short:
        # ending releases the whole pool, which would destroy boxes whose
        # players are still inside their investigation time.
        grace = max(
            float(os.environ.get("HUITZILOPOCHTLI_AUTO_END_GRACE_S", "300")),
            release_grace + 60.0)
        if terminal and now - float(last_end) >= grace:
            store.end_competition(comp.id)
            store.add_audit("system", "competition_auto_end", comp.id,
                            details_json=json.dumps(
                                {"grace_s": grace,
                                 "players": len(players)}))
            cleanup_pool(store, store.get_competition(comp.id))
            stats["auto_ended"] = stats.get("auto_ended", 0) + 1


def sweep(store: Store, server_secret: bytes, *,
          now: Optional[float] = None) -> dict:
    """Background maintenance that keeps dispensing automatic.

    For every live competition: retry claims that never got a VM (per-player
    exponential backoff, refreshing an expired join code first), advance
    provisioning tickets left behind by closed join pages, rotate the
    portal's join code on claimed VMs before it expires, and release boxes
    whose post-run access window (post_run_grace_s) has closed. Ended
    competitions get their pool released and deleted. Every competition is
    isolated: one failing (portal down, corrupt row) is backed off and never
    skips the rest. Best effort; never raises. Returns small counters for
    logging/tests.
    """
    now = time.time() if now is None else now
    stats = {"retried": 0, "polled": 0, "rotated": 0, "cleaned": 0,
             "auto_ended": 0, "deferred": 0, "released_boxes": 0,
             "release_errors": 0, "autowarmed": 0}
    if not enabled():
        return stats
    for comp in store.list_competitions():
        if _sweep_deferred(comp.id, now):
            stats["deferred"] += 1
            continue
        try:
            _sweep_one(store, comp, server_secret, now, stats)
        except Exception as exc:  # isolate one competition's failure
            _sweep_failed(comp.id, exc)
            continue
        _sweep_ok(comp.id)
    return stats


def reclaim(store: Store, comp: CompetitionRecord, player: PlayerRecord,
            *, back_url: str = "") -> dict:
    """Drop the current claim (if any) and ask the portal for a new VM."""
    if player.box_id:
        return {"ok": False, "error": "this slot already has a bound box"}
    if comp is None or comp.status != "live":
        message = "this competition is no longer live"
        _record_error(store, player, message)
        return {"ok": False, "error": message}
    base, _secret = config()
    if base and player.claim_uid and not player.box_id:
        try:
            workshop.release_vm(base, player.claim_uid)
        except workshop.WorkshopError:
            pass  # the reaper expires it; do not block the new claim
    store.update_player(
        player.player_id, claim_url=None, claim_uid=None, claim_ticket=None,
        claim_expires_at=None, claim_error=None, claim_attempts=0,
        claim_last_attempt_at=None, claim_last_poll_at=None)
    fresh = store.get_player(player.player_id)
    return start(store, comp, fresh, back_url=back_url)


def describe(player: PlayerRecord) -> dict:
    """The claim fields the join page/status JS needs (never the code itself)."""
    return {
        "claim_url": player.claim_url,
        "claim_pending": bool(player.claim_ticket and not player.claim_url),
        "claim_error": player.claim_error,
        "claim_attempts": player.claim_attempts or 0,
        "code_expires_at": player.join_code_expires_at,
        "box_bound": bool(player.box_id),
        "run_ends_at": player.ends_at,
    }
