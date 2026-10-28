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
import threading
import time
from typing import Optional

from engine import competition, scenario as scenario_mod, workshop
from engine.store import CompetitionRecord, PlayerRecord, Store

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
WARM_MAX = 64
WARM_WAIT_S = 900.0

#: comp id -> background warm job state. Process-local on purpose: it is a
#: progress indicator for the admin page, not durable competition state (the
#: pin and the portal's own pool are the source of truth).
_WARM_JOBS = {}
_WARM_LOCK = threading.Lock()

#: One provisioning attempt per engine process at a time. Concurrent first
#: claims on a fresh competition used to race the portal's single provision
#: job; the losers could pin a pool whose config another call had just
#: deleted (live load test: 15 simultaneous joins produced a permanently
#: stale pool pin and "Unknown code." for every later claim).
_POOL_LOCK = threading.Lock()
_PIN_CACHE = {}
_PIN_CACHE_LOCK = threading.Lock()


def config() -> tuple:
    """(portal base URL, prebind secret) from the environment."""
    base = os.environ.get("HUITZILOPOCHTLI_WORKSHOP_URL", "").rstrip("/")
    secret = os.environ.get("HUITZILOPOCHTLI_WORKSHOP_SECRET", "")
    return base, secret


def enabled() -> bool:
    return bool(config()[0])


def public_base() -> str:
    """Origin for back_url when there is no request to derive one from."""
    return os.environ.get("HUITZILOPOCHTLI_PUBLIC_URL", "").rstrip("/")


def _admin_password() -> str:
    return os.environ.get("HUITZILOPOCHTLI_WORKSHOP_ADMIN_PASSWORD", "")


def _back_url(comp: CompetitionRecord) -> str:
    base = public_base()
    return f"{base}/c/{comp.slug}/join/success" if base else ""


def ensure_pool(store: Store, comp: CompetitionRecord) -> tuple:
    """Serialize first-claim pool provisioning within the engine process."""
    with _POOL_LOCK:
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
        store.update_competition(comp.id, workshop_pool_code=None)
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
        return None, str(exc)
    _pin_pool(store, comp, result["pool_code"], "provisioned")
    return result["pool_code"], None


def _pin_pool(store: Store, comp: CompetitionRecord, pool_code: str,
              source: str) -> None:
    store.update_competition(comp.id, workshop_pool_code=pool_code)
    store.add_audit("system", "competition_pool", comp.id,
                    details_json=json.dumps({"pool": pool_code,
                                             "source": source}))
    print(f"competition {comp.slug}: workshop pool {pool_code} ({source})",
          flush=True)


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


def start_warm(store: Store, comp: CompetitionRecord, count) -> dict:
    """Start pre-deploying ``count`` boxes into the competition's pool.

    Returns the job state immediately; the work runs in a daemon thread so
    the admin page is not held open for the several minutes a cold batch
    takes. One job per competition at a time (a second click joins the
    running job instead of asking the portal for another batch).
    """
    try:
        count = int(count)
    except (TypeError, ValueError):
        return {"status": "error", "error": "Box count must be a number."}
    if count < 1 or count > WARM_MAX:
        return {"status": "error",
                "error": f"Box count must be between 1 and {WARM_MAX}."}
    with _WARM_LOCK:
        existing = _WARM_JOBS.get(comp.id)
        if existing is not None and existing.get("status") == "running":
            return dict(existing)
        job = {
            "status": "running", "requested": count,
            "pool_code": comp.workshop_pool_code,
            "available": 0, "total": 0, "in_use": 0,
            "started_at": time.time(), "finished_at": None, "error": None,
        }
        _WARM_JOBS[comp.id] = job
    threading.Thread(target=_warm_worker, name=f"warm-{comp.slug}",
                     args=(store, comp.id, count), daemon=True).start()
    return dict(job)


def _warm_worker(store: Store, comp_id: str, count: int) -> None:
    try:
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
    if not pool_code:
        with _POOL_LOCK:
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
        _warm_job_update(comp.id, pool_code=pool_code, available=available,
                         total=total, in_use=in_use)
        if available >= count:
            return {"status": "ready", "requested": count, "pool_code": pool_code,
                    "available": available, "total": total, "in_use": in_use,
                    "waited_s": round(time.time() - started, 1)}
        now = time.time()
        if now >= deadline:
            return {"status": "timeout", "requested": count,
                    "pool_code": pool_code, "available": available,
                    "total": total, "in_use": in_use,
                    "waited_s": round(now - started, 1),
                    "error": (f"only {available} of {count} boxes were ready "
                              f"after {int(now - started)} s")}
        # A brand-new pool is already provisioning `count` boxes. An existing
        # pool is topped up once; a 409 means an earlier portal job is still
        # running, so retry after it has had time to finish.
        if not topup_sent and now >= next_topup_at:
            try:
                workshop.provision_more(base, password, pool_code,
                                        count - available)
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


def _pool_vmids(base: str, password: str, prefix: str, pool_code: str,
                expected: int) -> list:
    """VMIDs the portal lists for this competition's pool.

    Pre-provisioned clones register asynchronously, so an operator who ends a
    competition immediately after its first claim can race the portal. When
    the pool reports a non-zero size, poll briefly before concluding there is
    nothing to destroy.
    """
    attempts = 5 if expected else 1
    for attempt in range(attempts):
        vms = workshop.list_vms(base, password)
        vmids = [v.get("vmid") for v in vms
                 if isinstance(v, dict)
                 and (str(v.get("student_id") or "").startswith(prefix)
                      or v.get("pool") == pool_code)]
        if vmids:
            return vmids
        if attempt + 1 < attempts:
            time.sleep(2.0)
    return []


def cleanup_pool(store: Store, comp: Optional[CompetitionRecord]) -> dict:
    """Release a competition's VMs and drop its pool once the run is over.

    Only pools this engine provisioned (name ``huitz-ranked-<slug>``) are
    released and deleted; a competition pinned to a pre-existing shared pool
    just has its pin cleared so the operator's pool stays untouched. Best
    effort and idempotent — the sweeper retries while the pin survives.
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
        if entry is not None and entry.get("name") != \
                workshop.competition_pool_name(comp.slug):
            stats["legacy"] = True
        elif entry is None:
            # The config is already gone (a failed provision, an operator
            # delete, or a crash between create and pin). There is nothing to
            # release or delete; clearing the pin is the whole cleanup, and
            # leaving it would make the sweeper retry a 404 forever.
            stats["pool_missing"] = True
        else:
            for p in store.list_players(comp.id):
                if p.claim_uid:
                    try:
                        workshop.release_vm(base, p.claim_uid)
                        stats["released"] += 1
                    except workshop.WorkshopError:
                        pass  # the portal expires it; do not block deletion
            # A dispenser pool pre-provisions clones that no player ever
            # claimed. Releasing player claims does not touch those, so
            # enumerate the portal's own VM list and destroy every clone
            # that belongs to this competition's pool.
            prefix = workshop.competition_pool_name(comp.slug) + "-"
            expected = int((entry or {}).get("count")
                           or (entry or {}).get("total") or 0)
            try:
                vmids = _pool_vmids(base, password, prefix, pinned, expected)
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
                stats["destroy_pending"] = job.get("status") != "done"
            try:
                workshop.delete_pool(base, password, pinned)
                stats["deleted"] = True
            except workshop.WorkshopError:
                return stats  # keep the pin; the sweeper retries
            # Deleting the config can race a clone registering itself. Sweep
            # once more now that the pool is gone; the portal keeps the VM
            # entry (and its pool code) even without a saved config.
            try:
                late = _pool_vmids(base, password, prefix, pinned, expected=0)
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
                stats["destroy_pending"] = (
                    stats["destroy_pending"] or job.get("status") != "done")
    store.update_competition(comp.id, workshop_pool_code=None)
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
            secret=secret or None, back_url=back_url)
    except workshop.WorkshopError as exc:
        # A pool can disappear between the pin check and the claim (the
        # portal's config file is not transactional with our pin). Treat the
        # portal's "Unknown code." as a stale pin: clear it, provision a fresh
        # pool, and retry once instead of leaving the player failing forever.
        if (comp.workshop_pool_code
                and "unknown code" in str(exc).lower()):
            store.update_competition(comp.id, workshop_pool_code=None)
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
                    secret=secret or None, back_url=back_url)
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
                result = workshop.claim_vm(base, pool)
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
    code = competition.generate_join_code()
    store.update_player(
        player.player_id,
        join_code_hash=competition.hash_join_code(server_secret, code),
        join_code_plain=code,
        join_code_expires_at=now + CODE_TTL_S)
    try:
        workshop.push_prebind(base, player.claim_uid, code, secret=secret,
                              back_url=back_url)
    except workshop.WorkshopError as exc:
        # Keep the code the player may already have; a portal outage must not
        # churn the fallback code out from under them.
        store.update_player(
            player.player_id, join_code_hash=old[0], join_code_plain=old[1],
            join_code_expires_at=old[2])
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
    code = competition.generate_join_code()
    store.update_player(
        player.player_id,
        join_code_hash=competition.hash_join_code(server_secret, code),
        join_code_plain=code,
        join_code_expires_at=now + CODE_TTL_S)


def sweep(store: Store, server_secret: bytes, *,
          now: Optional[float] = None) -> dict:
    """Background maintenance that keeps dispensing automatic.

    For every live competition: retry claims that never got a VM (per-player
    exponential backoff, refreshing an expired join code first), advance
    provisioning tickets left behind by closed join pages, and rotate the
    portal's join code on claimed VMs before it expires. Ended competitions
    get their pool released and deleted. Best effort; never raises. Returns
    small counters for logging/tests.
    """
    now = time.time() if now is None else now
    stats = {"retried": 0, "polled": 0, "rotated": 0, "cleaned": 0}
    if not enabled():
        return stats
    for comp in store.list_competitions():
        if comp.status == "ended" and comp.workshop_pool_code:
            # A pool outlives its competition only until the next sweep.
            cleanup_pool(store, comp)
            stats["cleaned"] += 1
            continue
        if comp.status != "live":
            continue
        back = _back_url(comp)
        for p in store.list_players(comp.id):
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
