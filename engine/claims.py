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
    """The competition's dedicated workshop pool, provisioned on demand.

    Each competition gets its own pool, cloned from the scenario record's
    ``pool`` block (the ranked template the box was built from) — the engine
    never selects among the portal's pre-existing pools, so a competition can
    never be handed a box of the wrong mode. Existing pins (older
    competitions, or a pool provisioned for this competition before an engine
    restart) are honored. Returns ``(pool_code, error)``; the error is a
    player-presentable string and is also what the sweeper retries on.
    """
    if comp.workshop_pool_code:
        return comp.workshop_pool_code, None
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
             "legacy": False, "destroy_pending": False}
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
        # The portal may not have the prebind secret yet. A plain claim still
        # gets the player a VM, so fall back to the manual join rather than
        # leaving them with nothing. This used to be silent, which meant an
        # operator who configured HUITZILOPOCHTLI_WORKSHOP_SECRET never
        # learned the advertised no-typing join was off (round 6 finding 6).
        if secret and "prebind" in str(exc).lower():
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
