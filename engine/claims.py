"""VM claim lifecycle for ranked joins: one VM per player slot, claimed from
the workshop portal. With the prebind secret the portal runs ``huitz join``
in-guest on first open, so the player types nothing. Each competition
provisions its own pool (``ensure_pool``) from the scenario's ``pool`` block —
the engine never picks among the portal's pre-existing pools. This module
never raises: every failure lands on the player row (``claim_error``).
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

WARM_MAX = 200
WARM_WAIT_S = 2400.0

#: comp id -> warm job state; process-local progress indicator, not durable
#: competition state (the pin and the portal's own pool are the source of truth).
_WARM_JOBS = {}
_WARM_LOCK = threading.Lock()

#: One provisioning attempt per COMPETITION at a time, not process-wide: a
#: slow pre-deploy in one event must not block the first join in another.
_POOL_LOCKS = {}
_POOL_LOCKS_LOCK = threading.Lock()

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


def lineup_of(store: Store, comp: CompetitionRecord) -> list:
    """The competition's scenario lineup [(name, version)]; always the mirror
    as a one-entry list for a single-scenario competition."""
    entries = store.get_competition_scenarios(comp.id)
    return entries or [(comp.scenario_name, comp.scenario_version)]


def is_multi(store: Store, comp: CompetitionRecord) -> bool:
    return len(store.get_competition_scenarios(comp.id)) > 1


def scenario_pool_name(comp_slug: str, scenario_name: str,
                       multi: bool) -> str:
    """The portal pool name for one lineup entry. Single-scenario competitions
    keep the exact legacy name (teardown anchors for live events are
    unchanged); multi-scenario entries carry the scenario slug so the
    competition's pools are pairwise distinct and each stays anchored on its
    own full name -- never a prefix of another."""
    legacy = workshop.competition_pool_name(comp_slug)
    if not multi:
        return legacy
    suffix = re.sub(r"[^a-z0-9]+", "-", (scenario_name or "").lower()).strip("-")
    return f"{legacy}-{(suffix or 'box')[:40]}"


def _pool_pin(store: Store, comp: CompetitionRecord, scenario_name: str,
              multi: bool) -> tuple:
    """(pool_code, pool_name) pinned for one lineup entry. Single-scenario
    reads the legacy mirror column (and its derived name) exactly as before."""
    if not multi:
        return comp.workshop_pool_code, pool_name_for(comp)
    row = store.get_competition_pool(comp.id, scenario_name)
    return (row[0], row[1]) if row else (None, None)


def _pool_clear(store: Store, comp: CompetitionRecord, scenario_name: str,
                multi: bool) -> None:
    if multi:
        store.pin_competition_pool(comp.id, scenario_name, None, None)
    else:
        store.update_competition(comp.id, workshop_pool_code=None,
                                 workshop_pool_name=None)


def ensure_pool(store: Store, comp: CompetitionRecord,
                scenario=None) -> tuple:
    """Serialize first-claim pool provisioning for one competition.

    Per-competition, not process-wide: two events starting at once must not
    queue behind each other, and each already has its own portal pool. A
    multi-box competition serializes per (competition, lineup entry): its
    pools are independent portal objects, and one slow template must not
    hold up the lineup's other claims.
    """
    if scenario is None:
        with _pool_lock(comp.id):
            return _ensure_pool_locked(store, comp, comp.scenario_name,
                                       comp.scenario_version)
    name, version = scenario
    multi = is_multi(store, comp)
    with _pool_lock(comp.id if not multi else f"{comp.id}|{name}"):
        return _ensure_pool_locked(store, comp, name, version)


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


def _ensure_pool_locked(store: Store, comp: CompetitionRecord,
                        scenario_name: str,
                        scenario_version: int) -> tuple:
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

    ``scenario_*`` select the lineup ENTRY being provisioned. For a
    single-scenario competition (the pre-v1.2 caller: entry == mirror) every
    read, name and pin below lands exactly where it used to.
    """
    multi = is_multi(store, comp)
    pinned, _pinned_name = _pool_pin(store, comp, scenario_name, multi)
    if pinned:
        base = config()[0]
        password = _admin_password()
        if not base or not password or _pin_is_alive(base, password, pinned):
            return pinned, None
        _pool_clear(store, comp, scenario_name, multi)
        store.add_audit("system", "competition_pool_stale", comp.id,
                        details_json=json.dumps(
                            {"pool": pinned, "scenario": scenario_name}))
        print(f"competition {comp.slug}: pinned pool {pinned} is gone; "
              "provisioning a fresh one", flush=True)
        comp = store.get_competition(comp.id)
    spec = scenario_mod.load_pool_spec(store, scenario_name, scenario_version)
    if not spec:
        return None, ("the scenario has no pool provisioning block; add a "
                      "'pool:' section to the ranked scenario, recompile, and "
                      "re-upload the engine record")
    base = config()[0]
    password = _admin_password()
    if not password:
        return None, "the workshop admin password is not configured"
    name = scenario_pool_name(comp.slug, scenario_name, multi)
    try:
        existing = workshop.find_pool_by_name(workshop.list_pools(base, password), name)
        if existing is not None:
            template = (existing.get("config") or {}).get("template_vm_id")
            if template is not None and template != spec.get("template_vm_id"):
                return None, (f"workshop pool {existing['code']} clones template "
                              f"{template}, not the scenario's "
                              f"{spec.get('template_vm_id')}; remove that pool "
                              "from the portal and retry")
            _pin_pool(store, comp, existing["code"], "reused",
                      scenario_name=scenario_name, multi=multi, name=name)
            return existing["code"], None
        result = workshop.provision_pool(base, password, comp.slug, spec,
                                         pool_name=name)
    except workshop.WorkshopError as exc:
        # The portal runs one provision job at a time: "already running" is a
        # transient queue — wait, then reuse the pool that appeared.
        if "already running" not in str(exc).lower():
            return None, str(exc)
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
                _pin_pool(store, comp, existing["code"], "reused_pending",
                          scenario_name=scenario_name, multi=multi, name=name)
                return existing["code"], None
        return None, ("the workshop portal is still provisioning another "
                      "pool; the claim will retry")
    _pin_pool(store, comp, result["pool_code"], "provisioned",
              scenario_name=scenario_name, multi=multi, name=name)
    return result["pool_code"], None


def _pin_pool(store: Store, comp: CompetitionRecord, pool_code: str,
              source: str, *, scenario_name: Optional[str] = None,
              multi: Optional[bool] = None,
              name: Optional[str] = None) -> None:
    if scenario_name is None:
        scenario_name = comp.scenario_name
    if multi is None:
        multi = is_multi(store, comp)
    if name is None:
        name = scenario_pool_name(comp.slug, scenario_name, multi)
    # The row write also maintains the competition-level mirror for the
    # position-0 entry (the only entry, pre-multi-box).
    store.pin_competition_pool(comp.id, scenario_name, pool_code, name)
    store.add_audit("system", "competition_pool", comp.id,
                    details_json=json.dumps({"pool": pool_code,
                                             "pool_name": name,
                                             "scenario": scenario_name,
                                             "source": source}))
    print(f"competition {comp.slug}: workshop pool {pool_code} "
          f"({name}, {source})", flush=True)


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


def live_pool_status(comp: CompetitionRecord, store=None) -> dict:
    """The competition pool's usable-box counts right now, from the portal.

    Cheap enough for the admin page's poll: one GET per render (one per pool
    for a lineup). Never raises -- portal trouble reads as
    ``{"status": "unavailable"}`` and no pool pin (nothing pre-deployed yet)
    as ``{"status": "unpinned"}``. With a ``store`` and a multi-scenario
    competition the counts aggregate over every pinned pool. ``templates``
    maps every pinned pool code to the template it clones, so the pre-deploy
    gate can hold each lineup entry to its own scenario's template."""
    pins = []
    if store is not None and is_multi(store, comp):
        pins = [code for _n, code, _nm
                in store.list_competition_pools(comp.id) if code]
        if not pins:
            return {"status": "unpinned"}
    else:
        if not comp.workshop_pool_code:
            return {"status": "unpinned"}
        pins = [comp.workshop_pool_code]
    base, _secret = config()
    password = _admin_password()
    if not base or not password:
        return {"status": "unavailable", "error": "the workshop portal is not configured"}
    available = total = 0
    pinned_seen = False
    templates = {}
    for code in pins:
        try:
            snap = workshop.pool_snapshot(base, password, code)
        except workshop.WorkshopError as exc:
            return {"status": "unavailable", "error": str(exc)[:200]}
        if snap is None:
            continue
        pinned_seen = True
        available += int(snap.get("available") or 0)
        total += int(snap.get("total") or 0)
        templates[code] = (snap.get("config") or {}).get("template_vm_id")
    if not pinned_seen:
        return {"status": "unpinned"}
    return {"status": "ok", "available": available, "total": total,
            "templates": templates,
            **({"pools": len(pins)} if len(pins) > 1 else {})}


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
    """Top the competition's pools back up to the auto-warm buffer.

    Runs from the claim sweep (every sweep interval, ~15 s) and after each
    successful claim. Reads each pinned pool's snapshot; if fewer boxes are
    available than the target, asks the portal for the deficit (the buffer is
    per pool, so a lineup keeps a buffer for every box of the lineup). Never
    raises: a portal blip is logged and left to the next tick. Returns the
    requested count (0 when nothing was asked for). A dead pin is left to the
    claim path's own recovery logic -- auto-warm never provisions a fresh pool.
    """
    target = autowarm_target()
    if not autowarm_enabled() or target < 1 or comp.status != "live":
        return 0
    base, _secret = config()
    password = _admin_password()
    if not (base and password):
        return 0
    now = time.time() if now is None else now
    multi = is_multi(store, comp)
    pins = [(s_name, code) for s_name, code, _nm
            in store.list_competition_pools(comp.id) if code]
    if not multi and comp.workshop_pool_code and \
            not any(code == comp.workshop_pool_code for _n, code in pins):
        pins.append((comp.scenario_name, comp.workshop_pool_code))
    total_deficit = 0
    for s_name, pool_code in pins:
        key = comp.id if not multi else f"{comp.id}|{s_name}"
        with _AUTOWARM_LAST_LOCK:
            if not force and now - _AUTOWARM_LAST.get(key, 0.0) \
                    < AUTOWARM_COOLDOWN_S:
                continue
            _AUTOWARM_LAST[key] = now
        try:
            snap = workshop.pool_snapshot(base, password, pool_code)
            if snap is None:
                continue
            deficit = target - int(snap.get("available") or 0)
            if deficit > 0:
                workshop.provision_more(base, password, pool_code, deficit)
                store.add_audit("system", "competition_autowarm", comp.id,
                                details_json=json.dumps(
                                    {"deficit": deficit, "target": target,
                                     "scenario": s_name}))
                if stats is not None:
                    stats["autowarmed"] = stats.get("autowarmed", 0) + 1
                total_deficit += deficit
        except workshop.WorkshopError as exc:
            print(f"competition {comp.slug}: auto-warm failed: {exc}", flush=True)
    return total_deficit


PORTAL_MISSING = ("The workshop portal is not configured "
                  "(HUITZILOPOCHTLI_WORKSHOP_URL), so there is nowhere to "
                  "pre-deploy boxes to.")
PORTAL_PASSWORD_MISSING = (
    "The workshop portal admin password "
    "(HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD) is not set, so the engine "
    "cannot ask the portal to clone boxes.")

POOL_SOURCE_MISSING_SHORT = "No pool to pre-deploy from"


def no_pool_message(scenario_name: str) -> str:
    """Why this scenario can clone nothing, and how to fix it."""
    return (f"No pool to pre-deploy from: the scenario '{scenario_name}' "
            "carries no pool block, so the engine has no ranked template to "
            "clone. Add a 'pool:' section to the ranked scenario (or an entry "
            "for it in the engine's pools file), recompile and re-upload the "
            "scenario, then reload this page.")


def _pool_template_mismatch(store: Store, comp: CompetitionRecord,
                            pool: dict) -> Optional[str]:
    """The first pinned pool cloning the wrong ranked template, or ``None``.

    A pool pointing at a template other than its lineup entry's would hand
    out the wrong box, so callers block the competition up front (before it
    opens) instead of only failing the first claim. ``pool`` is a
    ``live_pool_status`` snapshot: its ``templates`` map holds every pinned
    pool code's template, and a pin the portal said nothing about (or a
    scenario without a pool block) is skipped here -- the provision path
    enforces the same rule with the real spec at claim time.
    """
    templates = pool.get("templates") or {}
    if store is not None and is_multi(store, comp):
        pin_pairs = [(name, code) for name, code, _nm
                     in store.list_competition_pools(comp.id) if code]
        versions = dict(store.get_competition_scenarios(comp.id))
    else:
        pin_pairs = [(comp.scenario_name, comp.workshop_pool_code)]
        versions = {comp.scenario_name: comp.scenario_version}
    for name, code in pin_pairs:
        if not code:
            continue
        spec = scenario_mod.load_pool_spec(
            store, name, versions.get(name, comp.scenario_version))
        if not spec:
            continue
        template = templates.get(code)
        if (template is not None
                and template != spec.get("template_vm_id")):
            return (f"workshop pool {code} clones template "
                    f"{template}, not {name}'s "
                    f"{spec.get('template_vm_id')}; remove that pool "
                    "from the portal and retry")
    return None


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
    pinned = comp.workshop_pool_code
    if not pinned and is_multi(store, comp):
        # A lineup may have per-entry pins while the mirror lagged (the
        # position-0 pin always mirrors; a stale mirror must not read as
        # "nothing to pre-deploy from" when sibling pools exist).
        pinned = next((c for _n, c, _nm
                       in store.list_competition_pools(comp.id) if c), None)
    if pinned:
        if not check_pin:
            # Structural answer only: whether the pin is alive needs a portal
            # read the competition rows' poll must not make.
            return None
        if pool is not None:
            gone = pool.get("status") == "unpinned"
        else:
            gone = not _pin_is_alive(base, password, pinned)
        if not gone:
            # The pools are there; each must clone its lineup entry's ranked
            # template (see _pool_template_mismatch). With a handed-in
            # snapshot the templates are already known; a cold caller takes
            # one now, and a portal blip is not a mismatch -- the claim and
            # warm paths report the real transport error.
            snap_pool = pool if pool is not None else live_pool_status(
                comp, store)
            if isinstance(snap_pool, dict) and snap_pool.get("status") == "ok":
                return _pool_template_mismatch(store, comp, snap_pool)
            return None
    if not scenario_mod.load_pool_spec(store, comp.scenario_name,
                                       comp.scenario_version):
        return no_pool_message(comp.scenario_name)
    return None


def start_template_blocker(store: Store, comp: CompetitionRecord) -> Optional[str]:
    """The start gate: why the competition must not open, or ``None``.

    Unlike :func:`predeploy_blocker` this never demands a portal: a
    portal-less engine (development, the test tier) starts exactly as it did
    before the gate existed, and a missing or unreachable portal surfaces as
    the claim path's own error at the first join. What it does refuse is a
    verified misconfiguration -- a pinned pool that is alive and clones a
    template other than its scenario's, which would hand out the wrong box
    to every player.
    """
    if not config()[0] or not _admin_password():
        return None
    if not (comp.workshop_pool_code
            or (is_multi(store, comp)
                and any(c for _n, c, _nm
                        in store.list_competition_pools(comp.id) if c))):
        return None
    pool = live_pool_status(comp, store)
    if pool.get("status") != "ok":
        # No pool (nothing to pre-deploy from) or portal trouble: the claim
        # path reports those; neither is a proven wrong-template setup.
        return None
    return _pool_template_mismatch(store, comp, pool)


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
    # Checked twice: the blocker may read the portal outside the lock; the
    # re-check below registers under it, so simultaneous clicks start one batch.
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
            # provisioned the pool while this one waited.
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
            # The requested count is ADDITIVE to boxes already ready (a fresh
            # pool starts at zero): warming 2 into a pool of 12 aims for 14.
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

    Clones register asynchronously, so when the pool reports a non-zero size,
    poll briefly before concluding there is nothing to destroy; ``attempts``
    overrides that for the pool-config-already-gone case.

    Match is the pool code or a ``<pool name>-<n>`` student id ANCHORED on
    the full pool name — never a bare slug prefix (``demo`` must not destroy
    ``demo-2``'s clones).
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

    The portal reclaims VMs on its own ``expires_at`` (mirrored as the
    player's ``claim_expires_at``); an ``ends_at`` extension landing within
    ``margin_s`` of that instant could see the box torn down mid-overtime.
    The portal listing keys on VMID, not engine player, so every clone in
    this competition's pool gets the same bump.
    """
    base, _secret = config()
    password = _admin_password()
    multi = is_multi(store, comp)
    if multi:
        pins = [(s_name, code, name) for s_name, code, name
                in store.list_competition_pools(comp.id) if code]
    else:
        pins = ([(comp.scenario_name, comp.workshop_pool_code,
                  pool_name_for(comp))] if comp.workshop_pool_code else [])
    if not (base and password) or not pins:
        return {"bumped": False,
                "reason": "portal not configured or no pinned pool"}
    # A slot whose box-claim TTL is about to fall behind the team clock needs
    # its portal TTL bumped; the seat clock is one team clock, so every still
    # unreleased box of the seat shares the same deadline.
    tight = []
    for p in store.list_players(comp.id):
        if p.box_released_at or p.ends_at is None:
            continue
        for s in store.list_run_slots(p.player_id):
            if (s.box_id and not s.box_released_at
                    and s.claim_expires_at is not None
                    and p.ends_at + margin_s > s.claim_expires_at):
                tight.append((p, s))
    if not tight:
        # Seats without slot rows (never migrated/created): the players
        # mirror is their claim state, checked exactly like the old path.
        legacy = [p for p in store.list_players(comp.id)
                  if p.box_id and p.ends_at is not None
                  and p.claim_expires_at is not None
                  and p.ends_at + margin_s > p.claim_expires_at]
        if not legacy:
            return {"bumped": False, "reason": "portal reclaim clocks have headroom"}
        tight = [(p, None) for p in legacy]
    hours = max(1, -(-int(extension_s) // 3600))
    outcomes, needed = [], []
    for s_name, code, stored_name in pins:
        # The name goes in WITHOUT a trailing dash for single-pool comps:
        # _pool_vmids anchors ``<pool name>-<n>`` itself, and a dash here
        # would never match. Multi pins store their own full names.
        pool_name = stored_name or workshop.competition_pool_name(comp.slug)
        expected = int(getattr(store.get_competition(comp.id),
                               "max_players", 0) or 0) or len(tight)
        vmids = _pool_vmids(base, password, pool_name, code, expected,
                            attempts=2)
        needed.extend(vmids)
        if vmids:
            outcomes.extend(workshop.extend_vms(base, password, vmids, hours))
    if not outcomes:
        return {"bumped": False,
                "reason": "no portal VMs found for the pool",
                "needed_by": sorted({p.display_name for p, _s in tight})}
    return {"bumped": True, "hours": hours, "outcomes": outcomes}


def cleanup_pool(store: Store, comp: Optional[CompetitionRecord]) -> dict:
    """Release a competition's VMs and drop its pool(s) once the run is over.

    Only pools this engine provisioned (names anchored on this competition's
    slug) are released and deleted; a competition pinned to a pre-existing
    shared pool just has its pin cleared so the operator's pool stays
    untouched. Best effort and idempotent — the sweeper retries while any pin
    survives. A multi-scenario competition owns one pool per lineup entry, and
    every one is torn down here; a pin whose work failed keeps itself for the
    next sweep, and its successful siblings are already gone.

    The pool config can be gone while clones still live (a crash between
    provision and pin, an operator delete, or the mid-run engine restart that
    produced this round's leak). In that case we still enumerate the portal's
    VM list by pool code/student_id and destroy the clones; a missing config
    is never treated as "nothing to clean".
    """
    stats = {"released": 0, "destroyed": 0, "deleted": False,
             "legacy": False, "pool_missing": False,
             "destroy_pending": False}
    if comp is None:
        return stats
    multi = is_multi(store, comp)
    if multi:
        pins = [(s_name, code, name) for s_name, code, name
                in store.list_competition_pools(comp.id) if code]
    else:
        if not comp.workshop_pool_code:
            return stats
        pins = [(comp.scenario_name, comp.workshop_pool_code,
                 pool_name_for(comp))]
    if not pins:
        return stats
    base, _secret = config()
    password = _admin_password()
    # Release claimed VMs once, before any pool is destroyed: the uids are
    # the competition's, not per-pool, and a double release across pins would
    # only double the (best-effort) portal calls.
    released = 0
    if base and password:
        for p in store.list_players(comp.id):
            slots = store.list_run_slots(p.player_id)
            uids = {s.claim_uid for s in slots if s.claim_uid}
            if p.claim_uid:
                uids.add(p.claim_uid)  # the mirror's uid (deduped)
            for uid in sorted(uids):
                try:
                    workshop.release_vm(base, uid)
                    released += 1
                except workshop.WorkshopError:
                    pass  # the portal expires it; do not block cleanup
    for s_name, pinned, owned_name in pins:
        one = {"released": released if s_name == pins[0][0] else 0,
               "destroyed": 0, "deleted": False,
               "legacy": False, "pool_missing": False,
               "destroy_pending": False}
        done = _cleanup_pool_pin(store, comp, s_name, pinned, owned_name,
                                 multi, base, password, one)
        for key in ("released", "destroyed"):
            stats[key] += one[key]
        for key in ("deleted", "legacy", "pool_missing", "destroy_pending"):
            stats[key] = stats[key] or one[key]
        if done:
            _pool_clear(store, comp, s_name, multi)
            store.add_audit(
                "system", "competition_pool_cleanup", comp.id,
                details_json=json.dumps(
                    {"pool": pinned,
                     **({"scenario": s_name} if multi else {}), **one}))
            print(f"competition {comp.slug}: pool {pinned} cleaned up {one}",
                  flush=True)
    return stats


def _cleanup_pool_pin(store, comp, s_name, pinned, owned_name, multi,
                      base, password, stats) -> bool:
    """Tear down one pool pin. True when it is fully cleaned (the caller
    clears the pin); False keeps it for the next sweep's retry."""
    if not (base and password):
        return True  # nothing callable: clear the pin like the legacy tail did
    try:
        pools = workshop.list_pools(base, password)
    except workshop.WorkshopError:
        return False  # portal unreachable; the sweeper retries
    entry = next((p for p in pools if isinstance(p, dict)
                  and p.get("code") == pinned), None)
    if entry is not None and entry.get("name") != owned_name:
        stats["legacy"] = True
        return True  # not ours: drop the pin, leave the pool alone
    # (The competition's claimed VMs were already released by cleanup_pool;
    # destroy every clone that belongs to this pool, whether or not the
    # config still exists.)
    expected = int((entry or {}).get("count")
                   or (entry or {}).get("total") or 0)
    try:
        vmids = _pool_vmids(base, password, owned_name, pinned, expected,
                            attempts=None if entry is not None else 3)
    except workshop.WorkshopError:
        return False  # keep the pin; the sweeper retries
    if vmids:
        try:
            job = workshop.destroy_vms(base, password, vmids)
        except workshop.WorkshopError:
            return False
        if job.get("status") == "error":
            return False
        stats["destroyed"] += len(vmids)
        if job.get("status") != "done":
            stats["destroy_pending"] = True
            # Keep the pin: the destroy job is still running, and the
            # next sweep must verify the clones are actually gone.
            print(f"competition {comp.slug}: pool {pinned} destroy "
                  f"pending {stats}", flush=True)
            return False
    if entry is not None:
        try:
            workshop.delete_pool(base, password, pinned)
            stats["deleted"] = True
        except workshop.WorkshopError:
            return False  # keep the pin; the sweeper retries
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
            return False
        if job.get("status") == "error":
            return False
        stats["destroyed"] += len(late)
        if job.get("status") != "done":
            stats["destroy_pending"] = True
            print(f"competition {comp.slug}: pool {pinned} late destroy "
                  f"pending {stats}", flush=True)
            return False
    return True


def player_csrf(server_secret: bytes, player_id: str) -> str:
    return hmac.new(server_secret, b"claim:" + player_id.encode("utf-8"),
                    hashlib.sha256).hexdigest()


def check_csrf(server_secret: bytes, player_id: str, token) -> bool:
    return bool(token) and hmac.compare_digest(
        player_csrf(server_secret, player_id), str(token))


def _mirror_slot(store: Store, comp: CompetitionRecord,
                 player: PlayerRecord):
    """The seat's position-0 slot (the one the players.claim_* mirror
    follows), or None when the seat predates slot rows -- which puts every
    worker on the exact legacy code path."""
    return store.get_run_slot(player.player_id, comp.scenario_name)


def _set_claim_state(store: Store, comp: CompetitionRecord,
                     player: PlayerRecord, slot, **fields) -> None:
    """Write claim fields to the slot doing the work AND keep the mirror in
    step, in both directions:

    - a slot-None write (legacy single-box path, and any reader that treats
      the players row as the state) lands on players and on the position-0
      slot row, so the sweep never sees a row that disagrees with the page;
    - a write to the position-0 slot also lands on players;
    - a write to a secondary slot stays on that slot: the players mirror is
      the primary box's view, always.
    """
    mirror_name = comp.scenario_name if comp is not None else None
    if slot is None or slot.scenario_name == mirror_name:
        store.update_player(player.player_id, **fields)
    if slot is not None:
        store.update_run_slot(slot.slot_id, **fields)
    elif mirror_name is not None:
        m = store.get_run_slot(player.player_id, mirror_name)
        if m is not None:
            store.update_run_slot(m.slot_id, **fields)


def _record_error(store: Store, player: PlayerRecord, message,
                  slot=None) -> None:
    text = (str(message) or "claim failed").strip()[:500]
    attempts = ((slot.claim_attempts if slot is not None
                 else player.claim_attempts) or 0) + 1
    comp = store.get_competition(player.competition_id)
    _set_claim_state(store, comp, player, slot,
                     claim_error=text, claim_attempts=attempts,
                     claim_last_attempt_at=time.time())


def _apply_ready(store: Store, player: PlayerRecord, result: dict, *,
                 comp=None, slot=None) -> None:
    if comp is None:
        comp = store.get_competition(player.competition_id)
    attempts = ((slot.claim_attempts if slot is not None
                 else player.claim_attempts) or 0) + 1
    _set_claim_state(
        store, comp, player, slot,
        claim_url=result.get("open_url") or result.get("url"),
        claim_uid=result.get("uid"),
        claim_ticket=None,
        claim_expires_at=result.get("expires_at"),
        claim_error=None,
        claim_attempts=attempts,
        claim_last_attempt_at=time.time())
    # A box just left the unclaimed buffer: top it up in the background
    # (best effort; the per-competition cooldown stops rapid claims from
    # stacking jobs, and the sweep fills any remainder).
    threading.Thread(target=autowarm_thread_entry, name="autowarm-fire",
                     args=(store, player.competition_id),
                     daemon=True).start()


def autowarm_thread_entry(store: Store, competition_id: str) -> None:
    comp = store.get_competition(competition_id)
    if comp is not None:
        autowarm_tick(store, comp)


def start_seat(store: Store, comp: CompetitionRecord, player: PlayerRecord,
               *, back_url: str = "") -> list:
    """Claim every box of the seat's lineup that is still unbound.

    One call per lineup entry; a single-scenario competition is one call with
    slot=None -- byte-identical to the legacy join-claim thread. Returns the
    per-entry start() results.
    """
    comp = store.get_competition(comp.id) or comp
    slots = store.list_run_slots(player.player_id)
    if len(slots) <= 1:
        return [start(store, comp, player, back_url=back_url)]
    out = []
    for s in slots:
        fresh = store.get_player(player.player_id)
        if s.box_id:
            continue
        out.append(start(store, comp, fresh, back_url=back_url, slot=s))
    return out


def start(store: Store, comp: CompetitionRecord, player: PlayerRecord,
          *, back_url: str = "", slot=None) -> dict:
    """Claim a VM for an invited player. Best effort, stores the outcome.

    ``slot`` is the lineup entry being claimed (multi-box); with no slot the
    function addresses the seat's single box exactly as it always has.
    """
    box_id = slot.box_id if slot is not None else player.box_id
    claim_url = slot.claim_url if slot is not None else player.claim_url
    claim_ticket = (slot.claim_ticket if slot is not None
                    else player.claim_ticket)
    if box_id:
        return {"ok": True, "bound": True}
    if claim_url:
        return {"ok": True, "url": claim_url}
    if claim_ticket:
        return {"ok": True, "pending": True}
    base, secret = config()
    if not base:
        _record_error(store, player, "the workshop portal is not configured",
                      slot=slot)
        return {"ok": False, "error": "the workshop portal is not configured"}
    # Pools are picked automatically; resolve lazily so a competition created
    # while the portal was down still dispenses on the first join. Each
    # lineup entry has its own pool, cloned from its own scenario template.
    scenario = ((slot.scenario_name, slot.scenario_version)
                if slot is not None else None)
    pool, pool_err = ensure_pool(store, comp, scenario)
    if not pool:
        message = pool_err or "no workshop pool is available"
        _record_error(store, player, message, slot=slot)
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
        pinned = (slot is not None and
                  _pool_pin(store, comp, slot.scenario_name,
                            is_multi(store, comp))[0]) \
            or (comp.workshop_pool_code if slot is None or
                slot.scenario_name == comp.scenario_name else None)
        if pinned and "unknown code" in str(exc).lower():
            _pool_clear(store, comp,
                        slot.scenario_name if slot is not None
                        else comp.scenario_name,
                        is_multi(store, comp))
            store.add_audit("system", "competition_pool_stale", comp.id,
                            player.player_id,
                            details_json=json.dumps(
                                {"pool": pinned, "error": str(exc)[:200]}))
            print(f"competition {comp.slug}: claim hit a stale pool "
                  f"{pinned}; reprovisioning", flush=True)
            fresh = store.get_competition(comp.id)
            pool, pool_err = ensure_pool(store, fresh, scenario)
            if not pool:
                message = pool_err or "no workshop pool is available"
                _record_error(store, player, message, slot=slot)
                return {"ok": False, "error": message}
            try:
                result = workshop.claim_vm(
                    base, pool, code=player.join_code_plain or None,
                    secret=secret or None, back_url=back_url, timeout=45.0)
            except workshop.WorkshopError as exc2:
                _record_error(store, player, exc2, slot=slot)
                return {"ok": False, "error": str(exc2)}
        # A portal without prebind support still hands out a VM: fall back to
        # the manual join rather than leaving the player with nothing.
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
                _record_error(store, player, exc2, slot=slot)
                return {"ok": False, "error": str(exc2)}
        else:
            _record_error(store, player, exc, slot=slot)
            return {"ok": False, "error": str(exc)}
    if result.get("open_url") or result.get("url"):
        _apply_ready(store, player, result, comp=comp, slot=slot)
        return {"ok": True, "url": result.get("open_url") or result.get("url")}
    if result.get("ticket"):
        attempts = ((slot.claim_attempts if slot is not None
                     else player.claim_attempts) or 0) + 1
        _set_claim_state(store, comp, player, slot,
                         claim_ticket=result["ticket"],
                         claim_url=None, claim_error=None,
                         claim_attempts=attempts,
                         claim_last_attempt_at=time.time())
        return {"ok": True, "pending": True, "stage": result.get("stage")}
    _record_error(store, player, "the workshop portal returned no VM",
                  slot=slot)
    return {"ok": False, "error": "the workshop portal returned no VM"}


def poll(store: Store, player: PlayerRecord, *, now: Optional[float] = None,
         force: bool = False, slot=None) -> PlayerRecord:
    """Advance a provisioning ticket, with per-player throttling and backoff.

    Tickets are polled from the engine on behalf of every open join page, and
    the portal rate-limits redeem calls -- so never poll more than once per
    backoff window (which grows on consecutive failures). ``slot`` works on
    one lineup entry; with no slot the seat's mirror slot is used, falling
    back to the players row alone for seats that predate slot rows.
    """
    now = time.time() if now is None else now
    comp = store.get_competition(player.competition_id)
    box_id = slot.box_id if slot is not None else player.box_id
    claim_url = slot.claim_url if slot is not None else player.claim_url
    claim_ticket = (slot.claim_ticket if slot is not None
                    else player.claim_ticket)
    if box_id or claim_url or not claim_ticket:
        return player
    base, secret = config()
    if not base:
        return player
    tries = max(1, (slot.claim_attempts if slot is not None
                    else player.claim_attempts) or 1)
    backoff = min(POLL_MIN_INTERVAL * (2 ** (tries - 1)), MAX_POLL_BACKOFF)
    last_poll = (slot.claim_last_poll_at if slot is not None
                 else player.claim_last_poll_at) or 0
    if not force and now - last_poll < backoff:
        return player
    _set_claim_state(store, comp, player, slot, claim_last_poll_at=now)
    try:
        result = workshop.poll_ticket(base, claim_ticket,
                                      secret=secret or None)
    except workshop.WorkshopError as exc:
        _record_error(store, player, exc, slot=slot)
        return store.get_player(player.player_id)
    status = result.get("status")
    if status == "ready" and (result.get("open_url") or result.get("url")):
        _apply_ready(store, player, result, comp=comp, slot=slot)
    elif status in ("error", "expired"):
        _record_error(store, player, result.get("detail")
                      or "provisioning failed", slot=slot)
        _set_claim_state(store, comp, player, slot, claim_ticket=None)
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
    rotation is invisible. A lineup's unbound-but-claimed boxes all carry the
    same seat code (the box identifies its scenario itself; the code
    identifies the team), so the fresh code is pushed to every such VM.
    Returns True when a new code was pushed."""
    now = time.time() if now is None else now
    if (player.join_code_plain and player.join_code_expires_at
            and player.join_code_expires_at - now > CODE_REFRESH_MARGIN):
        return False
    comp = store.get_competition(player.competition_id)
    slots = store.list_run_slots(player.player_id)
    if slots:
        pending = [s for s in slots
                   if not s.box_id and s.claim_url and s.claim_uid]
    else:
        # Legacy seat without slot rows: the players mirror is the state.
        pending = ([player] if (not player.box_id and player.claim_url
                                and player.claim_uid) else [])
    if not pending:
        return False
    base, secret = config()
    if not base or not secret:
        return False
    old = (player.join_code_hash, player.join_code_plain,
           player.join_code_expires_at)
    try:
        code = mint_join_code(store, player, server_secret, now + CODE_TTL_S)
    except RuntimeError as exc:
        _record_error(store, player, str(exc))
        return False
    pushed_any = False
    for s in pending:
        try:
            workshop.push_prebind(base, s.claim_uid, code, secret=secret,
                                  back_url=back_url)
            pushed_any = True
        except workshop.WorkshopError as exc:
            if getattr(exc, "status", None) in (404, 405):
                # This portal has no /api/prebind: it hands out a VM but never
                # stores a code. The player still types the code by hand, so
                # keep the fresh one (the old one may already be expired) and
                # stop surfacing a portal-shape mismatch as an error.
                store.add_audit(
                    "system", "prebind_unavailable", player.competition_id,
                    player.player_id,
                    details_json=json.dumps({"error": str(exc)[:200]}))
                store.update_player(player.player_id, claim_error=None)
                return True
            # A real portal outage for this one VM: the others still got the
            # code, and the next tick retries the rest.
            _record_error(store, player,
                          f"could not update the VM's join code: {exc}",
                          slot=s if s is not player else None)
    if not pushed_any:
        # Every push failed on a real outage: keep the code the player may
        # already have typed.
        try:
            store.update_player(
                player.player_id, join_code_hash=old[0],
                join_code_plain=old[1], join_code_expires_at=old[2])
        except JoinCodeCollision:
            # Another slot took the old code meanwhile; the fresh code is the
            # better answer for this player.
            pass
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


#: comp id -> (retry_after, consecutive_failures): a portal-backed sweep error
#: backs off that competition only — never retried every tick, and it never
#: starves the other competitions.
_SWEEP_BACKOFF = {}
_SWEEP_BACKOFF_LOCK = threading.Lock()
SWEEP_MAX_BACKOFF_S = 600.0
SWEEP_BASE_BACKOFF_S = 30.0
#: players per competition per tick, rotated so a huge roster cannot
#: monopolize one sweep.
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
        # A seat's unbound lineup entries still need claim work even after
        # the first box joined (which flips the seat to running): invited or
        # running seats with at least one unbound slot are worked. Removed /
        # finished / disqualified seats are terminal for claiming, exactly
        # as a finished single-box player's box used to be skipped.
        if p.status not in ("invited", "running"):
            continue
        slots = store.list_run_slots(p.player_id) or [None]
        single = len(store.get_competition_scenarios(comp.id)) <= 1
        handled_rotate = False
        for s in slots:
            # A single-scenario seat keeps the exact legacy rule: only an
            # invited, still-unbound seat needs claim work at all. A multi
            # seat works EVERY unbound lineup entry (running included -- its
            # later boxes may still be waiting on a VM), reading the primary
            # entry's state from the players mirror and secondaries' from
            # their slot rows.
            primary = s is None or s.scenario_name == comp.scenario_name
            if single:
                if p.status != "invited" or p.box_id:
                    continue
                work_slot, url, ticket = None, p.claim_url, p.claim_ticket
                last, att = p.claim_last_attempt_at, p.claim_attempts
            elif primary:
                if s.box_id:
                    continue
                work_slot = s
                url, ticket = p.claim_url, p.claim_ticket
                last, att = p.claim_last_attempt_at, p.claim_attempts
            else:
                if s.box_id:
                    continue
                work_slot = s
                url, ticket = s.claim_url, s.claim_ticket
                last, att = s.claim_last_attempt_at, s.claim_attempts
            if url:
                if not handled_rotate:
                    handled_rotate = True
                    if rotate_code_if_needed(store, p, server_secret,
                                             back_url=back, now=now):
                        stats["rotated"] += 1
                continue
            if ticket:
                poll(store, p, now=now, slot=None if single else work_slot)
                stats["polled"] += 1
                continue
            if now - (last or 0) < _retry_backoff(att):
                continue
            _refresh_expired_code(store, server_secret, p, now)
            fresh = store.get_player(p.player_id)
            out = start(store, comp, fresh, back_url=back,
                        slot=None if single else work_slot)
            if out.get("ok"):
                stats["retried"] += 1
    # Auto-warm: refill the pool's unclaimed buffer (self-cooled; see
    # autowarm_tick). After the player work so a claim this tick just won
    # counts against the snapshot.
    autowarm_tick(store, comp, now=now, stats=stats)
    # Post-run access window: after the run clock ends the box stays up
    # post_run_grace_s for investigation, then is released (destroy via the
    # portal, seat freed). The governing end is ``finished_at`` when a
    # check-in confirmed it, else ``ends_at`` — the clock is the truth. If the
    # competition ends first, the End path's pool teardown releases everything.
    base, _secret = config()
    release_grace = post_run_grace_s()
    if base:
        single = len(store.get_competition_scenarios(comp.id)) <= 1
        for p in store.list_players(comp.id):
            # Release each box of the seat whose access window has closed.
            # The seat's clock is one team clock, so all of its boxes close
            # together; slots that never bound simply never enter the loop.
            # Single-scenario seats are read from the players mirror
            # verbatim -- the legacy loop.
            if single:
                items = [(p.box_id, p.claim_uid, p.box_released_at, None)]
            else:
                items = [(s.box_id, s.claim_uid, s.box_released_at, s)
                         for s in store.list_run_slots(p.player_id)]
            for box_id, uid, released_at, s in items:
                if not (box_id and uid) or released_at:
                    continue
                run_end = max(p.finished_at or 0.0, p.ends_at or 0.0)
                if not run_end or now < run_end + release_grace:
                    continue
                try:
                    workshop.release_vm(base, uid)
                except workshop.WorkshopError:
                    stats["release_errors"] += 1
                    continue  # best effort; the next sweep retries
                store.release_player_box(
                    p.player_id, now,
                    scenario_name=s.scenario_name if s is not None else None)
                store.add_audit("system", "player_box_released", comp.id,
                                p.player_id,
                                details_json=json.dumps(
                                    {"grace_s": release_grace,
                                     "ended_at": run_end, "uid": uid,
                                     **({"scenario": s.scenario_name}
                                        if s is not None else {})}))
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
            *, back_url: str = "", slot=None) -> dict:
    """Drop the current claim (if any) and ask the portal for a new VM.

    ``slot`` re-claims one lineup entry's box; without it the seat's single
    box -- the legacy behavior, byte for byte.
    """
    if slot is not None:
        if slot.box_id:
            return {"ok": False, "error": "this slot already has a bound box"}
        uid, box_id = slot.claim_uid, slot.box_id
    else:
        uid, box_id = player.claim_uid, player.box_id
    if box_id:
        return {"ok": False, "error": "this slot already has a bound box"}
    if comp is None or comp.status != "live":
        message = "this competition is no longer live"
        _record_error(store, player, message, slot=slot)
        return {"ok": False, "error": message}
    base, _secret = config()
    if base and uid:
        try:
            workshop.release_vm(base, uid)
        except workshop.WorkshopError:
            pass  # the reaper expires it; do not block the new claim
    _set_claim_state(store, comp, player, slot,
                     claim_url=None, claim_uid=None, claim_ticket=None,
                     claim_expires_at=None, claim_error=None,
                     claim_attempts=0, claim_last_attempt_at=None,
                     claim_last_poll_at=None)
    fresh = store.get_player(player.player_id)
    return start(store, comp, fresh, back_url=back_url, slot=slot)


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
