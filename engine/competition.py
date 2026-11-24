"""Ranked competition domain logic: competitions, players, runs, join.

All state lives in engine.store. This module is pure business logic except
for the signed /join verification and the leaderboard shaping used by the
HTTP layer.
"""
import base64
import datetime
import hashlib
import hmac
import html
import json
import math
import re
import secrets
import time
from typing import Optional

from common import canon
from common.crypto import signing
from common.schema import SCHEMA_VERSION
from engine import scenario as scenario_mod
from engine import verify_gate
from engine.store import (CompetitionRecord, JoinCodeCollision, PlayerRecord,
                          Store)

# Unambiguous alphabet (no 0/O/1/I/L) for codes that get typed off a screen.
_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
_CODE_LEN = 4
_NAME_MAX = 40
_SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
_WS_RE = re.compile(r"\s+")

#: A player occupies exactly one competition slot until their run ends.
ACTIVE_PLAYER_STATUSES = ("invited", "running")


def is_active_player(player: Optional[PlayerRecord],
                     comp: Optional[CompetitionRecord]) -> bool:
    """True while ``player`` is competing in a live competition.

    "Competing" covers both the reserved-but-not-yet-bound slot (invited) and
    the running clock. A player whose competition has ended (or whose slot was
    removed/disqualified/finished) is free to join another competition.
    """
    return (player is not None and comp is not None
            and comp.status == "live"
            and player.status in ACTIVE_PLAYER_STATUSES)


def normalize_name(name: str) -> str:
    return _WS_RE.sub(" ", name.strip()).lower()


def validate_display_name(name) -> Optional[str]:
    if not isinstance(name, str):
        return "Name must be text."
    cleaned = _WS_RE.sub(" ", name.strip())
    if not cleaned:
        return "Name is required."
    if len(cleaned) > _NAME_MAX:
        return f"Name must be at most {_NAME_MAX} characters."
    if any(ord(ch) < 32 for ch in cleaned):
        return "Name contains control characters."
    return None


def validate_slug(slug) -> Optional[str]:
    if not isinstance(slug, str) or not _SLUG_RE.match(slug):
        return "Slug must be lowercase letters, digits and hyphens (2-64 chars)."
    return None


def generate_join_code() -> str:
    return "".join(secrets.choice(_CODE_ALPHABET) for _ in range(_CODE_LEN))


def hash_join_code(server_secret: bytes, code: str) -> str:
    return hmac.new(server_secret, code.strip().upper().encode("utf-8"),
                    hashlib.sha256).hexdigest()


def _remaining_from(end: Optional[float], now: float) -> int:
    """Seconds left until ``end`` (0 once past it or when there is no end)."""
    return max(0, int((end or 0) - now))


def effective_run_end(comp: Optional[CompetitionRecord],
                      player: PlayerRecord) -> Optional[float]:
    """When this run actually stops: the run clock, or the scheduled end.

    A scheduled competition end (``scheduled_end_at``) is a hard ceiling on
    every run still in progress: once it arrives the competition ends and
    the run stops with it, so a live countdown must aim at the earlier of
    the two deadlines. Only a live competition's schedule binds — an ended
    competition has already frozen every run at its ``ends_at``.
    """
    end = player.ends_at if player is not None else None
    scheduled = getattr(comp, "scheduled_end_at", None) if comp is not None else None
    if (comp is not None and comp.status == "live"
            and scheduled is not None and (end is None or scheduled < end)):
        return scheduled
    return end


def _service_rows(store: Store, comp: CompetitionRecord,
                  box_id: Optional[str], rubric_sla_ids: Optional[set] = None) -> list:
    services = scenario_mod.load_services(store, comp.scenario_name,
                                          comp.scenario_version)
    if not services:
        return []
    states = {}
    if box_id:
        for svc in services:
            cid = svc.get("check_id")
            rec = store.get_sla_state(box_id, cid)
            if rec is not None:
                states[cid] = rec
    out = []
    for svc in services:
        cid = svc.get("check_id")
        rec = states.get(cid)
        out.append({
            "id": svc.get("id"),
            "display": svc.get("display") or svc.get("id"),
            "check_id": cid,
            "state": rec.state if rec is not None else "PENDING",
            "accrued_points": rec.accrued_points if rec is not None else 0,
            "last_changed_at": rec.last_changed_at if rec is not None else None,
            # Oldest -> newest post-hysteresis observations (bounded by
            # common.schema.SLA_HISTORY_MAX). Both the portal and the on-box
            # report render this as the service's "last 10 ticks" strip.
            "history": list(rec.history) if rec is not None else [],
        })
    return out


def service_rows(store: Store, comp: CompetitionRecord,
                 box_id: Optional[str] = None) -> list:
    """Public service rows for a player, including before their box joins.

    An unbound slot still shows every scored service (state PENDING, empty
    history) so the dashboard's uptime strip has real names from the start.
    """
    return _service_rows(store, comp, box_id)


def _scored_players(store: Store, comp: CompetitionRecord, now: float) -> list:
    """(player, effective status, score, total) in scoreboard order.

    One ordering function for the public board and the per-box rank shown in
    the ranked report: totals first, then the stable started_at/player_id
    ordering. Equal totals share a rank (standard competition ranking:
    1, 2, 2, 4); the ordering keys only decide display order. A player whose
    clock has run out is treated as finished even if no check-in has
    persisted that status yet.
    """
    # A player is on the board only once a box is bound: a slot that has not
    # connected yet must never look like a zero-point competitor.
    players = [p for p in store.list_players(comp.id)
               if p.status in ("running", "finished") and p.box_id]
    scored = []
    for p in players:
        status = p.status
        # The run's effective deadline includes a scheduled competition end:
        # once that wall time passes the run is over even before the sweeper
        # has persisted the competition's end (same lazy-finish rule as the
        # per-player clock: the clock is the truth, the row catches up).
        effective_end = effective_run_end(comp, p)
        if status == "running" and effective_end is not None and now >= effective_end:
            status = "finished"
        score = store.get_score(p.box_id) if p.box_id else None
        total = score["total"] if score else 0
        scored.append((p, status, score, total))
    scored.sort(key=lambda item: (
        -item[3], item[0].started_at or 0, item[0].player_id))
    return scored


def _shared_rank(scored: list, total: int) -> int:
    """Standard competition rank for ``total`` on ``scored`` (1,2,2,4)."""
    return 1 + sum(1 for _p, _s, _sc, row_total in scored
                   if row_total > total)


def rank_for_player(store: Store, comp: Optional[CompetitionRecord],
                    player: Optional[PlayerRecord],
                    now: Optional[float] = None) -> "tuple[Optional[int], Optional[int]]":
    """(position, total players) for ``player`` on the live scoreboard.

    Returns (None, None) for a box that is not attached to a competition, and
    (None, total) if the player is no longer on the board (e.g. removed).
    Equal totals share a position. The identity comparison is by player_id,
    not object identity.
    """
    if comp is None or player is None:
        return None, None
    now = time.time() if now is None else now
    scored = _scored_players(store, comp, now)
    for row_player, _status, _score, total in scored:
        if row_player.player_id == player.player_id:
            return _shared_rank(scored, total), len(scored)
    return None, len(scored)


def _row_for(store: Store, comp: CompetitionRecord, p, status, score, total,
             now: float) -> dict:
    """One leaderboard row, shared by the public payload and player_board_row."""
    return {
        "player_id": p.player_id,
        "name": p.display_name,
        "status": status,
        "total": total,
        "hardening_points": score["hardening_points"] if score else 0,
        "service_points": score["service_points"] if score else 0,
        "forensics_points": (score.get("forensics_points", 0)
                             if score else 0),
        # Checks the agent reported `unavailable` at the last check-in
        # (required software missing); 0 keeps healthy rows unchanged.
        "ungraded_count": (score.get("ungraded_count", 0) if score else 0),
        "started_at": p.started_at,
        "ends_at": p.ends_at,
        # Countdown target: the run clock or an earlier scheduled
        # competition end (effective_run_end), whichever is sooner.
        "remaining_s": (_remaining_from(effective_run_end(comp, p), now)
                        if status == "running" else 0),
        "last_checkin": score["updated_at"] if score else None,
        "services": _service_rows(store, comp, p.box_id),
        "box_bound": bool(p.box_id),
    }


def player_board_row(store: Store, comp: CompetitionRecord, player,
                     now: Optional[float] = None) -> Optional[dict]:
    """The leaderboard row for one player, even when the public board is hidden.

    A hidden leaderboard withholds everyone's standings, but a player's own
    score and rank are their own data (the on-box report shows them too), so
    /me and the run home page use this: a hidden board must never read as
    "not joined" or "waiting for the first check-in". Returns None when the
    player has no scored check-in yet. Adds ``board_total`` (players on the
    board) so the rank line can say "of N" without the public rows.
    """
    now = time.time() if now is None else now
    scored = _scored_players(store, comp, now)
    for p, status, score, total in scored:
        if p.player_id == player.player_id:
            row = _row_for(store, comp, p, status, score, total, now)
            row["rank"] = _shared_rank(scored, total)
            row["board_total"] = len(scored)
            return row
    return None


def leaderboard_payload(store: Store, comp: CompetitionRecord,
                        now: Optional[float] = None) -> dict:
    now = time.time() if now is None else now
    rows = []
    if not comp.leaderboard_hidden:
        for p, status, score, total in _scored_players(store, comp, now):
            rows.append(_row_for(store, comp, p, status, score, total, now))
    previous_total = None
    previous_rank = 0
    for position, row in enumerate(rows, start=1):
        if row["total"] != previous_total:
            previous_rank = position
            previous_total = row["total"]
        row["rank"] = previous_rank
    return {
        "competition": public_competition_payload(store, comp, now=now),
        "leaderboard": rows,
        "generated_at": now,
    }


def public_competition_payload(store: Store, comp: CompetitionRecord,
                               now: Optional[float] = None) -> dict:
    now = time.time() if now is None else now
    count = store.count_players(comp.id)
    # Reserved-but-unprovisioned seats, reported apart so a name waiting for
    # a VM reads as what it is instead of a zero-point competitor (the board
    # lists players only once a box is bound) or a phantom.
    waiting = store.count_waiting_players(comp.id)
    theme = {}
    if comp.theme_json:
        try:
            theme = json.loads(comp.theme_json) or {}
        except (ValueError, TypeError):
            theme = {}
    return {
        "id": comp.id,
        "slug": comp.slug,
        "name": comp.name,
        "scenario_name": comp.scenario_name,
        "scenario_version": comp.scenario_version,
        "status": comp.status,
        "join_open": bool(comp.join_open),
        "leaderboard_hidden": bool(comp.leaderboard_hidden),
        "max_players": comp.max_players,
        "player_count": count,
        "waiting_count": waiting,
        "duration_s": comp.duration_s,
        "started_at": comp.started_at,
        "ended_at": comp.ended_at,
        # Wall-clock automatic end for the whole competition (None = none).
        # Runs still in progress stop when it arrives; the competitor pages
        # count down to it.
        "scheduled_end_at": getattr(comp, "scheduled_end_at", None),
        "theme": theme,
        "join_instructions": comp.join_instructions,
        "can_join": (comp.status == "live" and comp.join_open
                     and (comp.max_players <= 0 or count < comp.max_players)),
    }


def extend_runs(store: Store, comp: CompetitionRecord, seconds: int, *,
                now: Optional[float] = None) -> dict:
    """Grant overtime to a live competition's runs (admin action).

    Runs are scored purely from the engine receipt clock against the stored
    ``ends_at``, so an extension is a metadata move, not a scoring change:
    every running clock slides forward by ``seconds``. A run already frozen
    as ``finished`` by expiry (the only way an actively-participating player
    ends up ``finished``) resumes on an even footing: its deadline restarts
    at ``now + seconds``. A run whose box was already released after the
    post-run access window is skipped: there is no agent to resume. Slots
    that never claimed a box (invited) have no
    clock to extend -- their join codes are refreshed by the claim sweep --
    and removed/disqualified slots are never touched.

    Returns a report the admin API forwards verbatim; the caller audits it.
    """
    now = time.time() if now is None else now
    if comp.status != "live":
        raise ExtendRefused("only a live competition can be extended")
    seconds = int(seconds)
    if seconds <= 0 or seconds > 6 * 3600:
        raise ExtendRefused("extension must be between 1 minute and 6 hours")
    extended, resumed, skipped = [], [], []
    for p in store.list_players(comp.id):
        if p.box_released_at:
            # The post-run access window already closed (or an admin released
            # the box): the VM is destroyed, so there is no agent to resume.
            skipped.append({"name": p.display_name, "status": p.status,
                            "reason": "box released"})
            continue
        if p.status == "running" and p.ends_at is not None:
            store.update_player(p.player_id, ends_at=p.ends_at + seconds)
            extended.append({"player_id": p.player_id,
                             "name": p.display_name,
                             "ends_at": p.ends_at + seconds})
        elif p.status == "finished" and p.box_id:
            store.update_player(p.player_id, status="running", finished_at=None,
                                ends_at=now + seconds)
            resumed.append({"player_id": p.player_id,
                            "name": p.display_name,
                            "ends_at": now + seconds})
        elif p.status in ("invited", "running"):
            # invited: no clock yet; running without ends_at cannot happen,
            # but leave anything unexplainable untouched and say so.
            skipped.append({"name": p.display_name, "status": p.status})
        # removed/disqualified stay untouched, by design.
    return {"minutes": seconds // 60, "seconds": seconds,
            "extended": extended, "resumed": resumed, "skipped": skipped}


class ExtendRefused(Exception):
    """The competition is not in a state that accepts an extension."""


#: A scheduled end may sit at most this far in the future (30 days) — far
#: enough for any multi-day event, tight enough to catch a fat-fingered year.
MAX_SCHEDULE_HORIZON_S = 30 * 24 * 3600


class ScheduleRefused(Exception):
    """The competition is not in a state that accepts a scheduled end."""


def parse_scheduled_end(raw: str, now: float) -> float:
    """Parse an admin-supplied wall-clock time into an epoch (local time).

    Accepts the datetime-local forms a browser sends (``YYYY-MM-DDTHH:MM``
    and with ``:SS``), the same with a space instead of ``T``, and full ISO
    strings with an explicit offset (honored as-is). A naive time is read in
    the engine's local zone — the same zone every page renders timestamps
    in. The value must land strictly in the future and within
    ``MAX_SCHEDULE_HORIZON_S``; anything else raises ``ScheduleRefused``.
    """
    text = (raw or "").strip()
    if not text:
        raise ScheduleRefused("no time given")
    normalized = text.replace(" ", "T", 1) if " " in text and "T" not in text else text
    try:
        parsed = datetime.datetime.fromisoformat(normalized)
    except ValueError:
        raise ScheduleRefused(
            "could not read that time; use YYYY-MM-DD HH:MM (server time)")
    if parsed.tzinfo is None:
        parsed = parsed.astimezone()  # naive -> engine's local zone
    when = parsed.timestamp()
    if not math.isfinite(when):
        raise ScheduleRefused("could not read that time")
    if when <= now:
        raise ScheduleRefused("that time is in the past; pick a future moment")
    if when > now + MAX_SCHEDULE_HORIZON_S:
        raise ScheduleRefused("that time is too far out (30 days at most)")
    return when


def format_scheduled_end(when: Optional[float]) -> str:
    """Human form for flash messages and audit rows (server-local time)."""
    if not when:
        return ""
    return datetime.datetime.fromtimestamp(float(when)).strftime("%Y-%m-%d %H:%M")


def schedule_end(store: Store, comp: CompetitionRecord,
                 when: Optional[float], *, now: Optional[float] = None) -> CompetitionRecord:
    """Set (``when`` as an epoch) or clear (``None``) the competition's
    scheduled end and return the fresh record.

    The schedule is metadata, exactly like ``Extend``: nothing about the box
    side changes when it is set. When the time arrives, the sweeper ends the
    competition exactly as an admin End would — every run still in progress
    stops, the score freezes, and the pool is torn down.
    """
    now = time.time() if now is None else now
    if comp.status not in ("draft", "live"):
        raise ScheduleRefused(
            f"only a draft or live competition can schedule its end; "
            f"this one is {comp.status}")
    if when is not None:
        when = float(when)
        if when <= now:
            raise ScheduleRefused("that time is in the past; pick a future moment")
        if when > now + MAX_SCHEDULE_HORIZON_S:
            raise ScheduleRefused("that time is too far out (30 days at most)")
    store.update_competition(comp.id, scheduled_end_at=when)
    return store.get_competition(comp.id)


def sweep_scheduled_ends(store: Store, *, now: Optional[float] = None,
                         cleanup=None) -> list:
    """End every live competition whose scheduled end has arrived.

    Runs once per sweep tick, before and independent of the VM-claim sweep:
    a scheduled end must fire even where no workshop portal is configured.
    Ending is the exact admin-End path (``end_competition`` freezes every
    still-running player at the receipt clock, then the pool teardown
    releases the boxes); ``cleanup`` is the caller-injected pool teardown
    (``claims.cleanup_pool`` — importing it here would be circular, and the
    regular sweeper re-runs pool cleanup for ended competitions anyway, so a
    ``None`` merely defers the VM work one tick). Returns one summary dict
    per ended competition for logging and tests. Best effort per competition:
    one failure never skips the others.
    """
    now = time.time() if now is None else now
    ended = []
    for comp in store.list_competitions():
        if comp.status != "live":
            continue
        scheduled = getattr(comp, "scheduled_end_at", None)
        if not scheduled or now < scheduled:
            continue
        try:
            stopped = store.end_competition(comp.id)
            if not stopped:
                continue  # already ended between the read and the write
            store.add_audit("system", "competition_scheduled_end", comp.id,
                            details_json=json.dumps({
                                "scheduled_end_at": scheduled,
                                "scheduled_end": format_scheduled_end(scheduled),
                                "fired_at": now}))
            summary = {"slug": comp.slug, "scheduled_end_at": scheduled}
            if cleanup is not None:
                try:
                    summary["pool"] = cleanup(store, store.get_competition(comp.id))
                except Exception as exc:  # VM work is best effort; never fatal
                    summary["pool_error"] = str(exc)[:200]
            ended.append(summary)
        except Exception:  # isolate one competition's failure
            continue
    return ended


def handle_join(store: Store, body: dict, sig: bytes, server_secret: bytes,
                now: Optional[float] = None) -> tuple:
    """Verify and bind a box to a player. Returns (status, payload).

    status is an HTTP status code; payload is a JSON-able dict.
    """
    now = time.time() if now is None else now
    required = {
        "join_code": str, "box_id": str, "public_key": str,
        "agent_version": str, "scenario_name": str, "scenario_version": int,
    }
    if not isinstance(body, dict):
        return 400, {"error": "malformed body: expected a JSON object"}
    for key, typ in required.items():
        if key not in body:
            return 400, {"error": f"malformed body: missing {key}"}
        if key == "scenario_version":
            if isinstance(body[key], bool) or not isinstance(body[key], int):
                return 400, {"error": "malformed body: scenario_version has wrong type"}
        elif not isinstance(body[key], typ) or not body[key]:
            return 400, {"error": f"malformed body: {key} has wrong type"}
    if len(body["box_id"]) > 128:
        return 400, {"error": "malformed body: box_id too long"}
    try:
        public_key = base64.b64decode(body["public_key"], validate=True)
    except Exception:
        return 400, {"error": "malformed body: public_key is not valid base64"}
    canonical_bytes = canon.canonicalize(body)
    verified = verify_gate.verify(public_key, canonical_bytes, sig)
    if verified is None:
        return 503, {"error": "engine busy verifying signatures; retry"}
    if not verified:
        return 403, {"error": "bad signature"}
    code = str(body.get("join_code", "")).strip().upper()
    if not code:
        return 403, {"error": "invalid join code"}
    code_hash = hash_join_code(server_secret, code)
    status, player, comp = store.bind_player_box_atomic(
        code_hash, body["box_id"], body["public_key"], body["scenario_name"],
        body["scenario_version"], now=now,
    )
    if status != "ok":
        messages = {
            "unknown_code": (403, "invalid join code"),
            "expired_code": (410, "join code expired; ask the admin for a new one"),
            "not_live": (409, "competition is not accepting joins"),
            "full": (409, "competition is full"),
            "scenario_mismatch": (409, "this box was built for a different scenario"),
            "already_joined": (409, "this player already has a box"),
            "duplicate_box": (409, "this box is already enrolled"),
        }
        code_, msg = messages.get(status, (409, status))
        return code_, {"error": msg}
    store.add_audit("system", "join", comp.id, player.player_id,
                    details_json='{"box_id": %s}' % json.dumps(body["box_id"]))
    return 200, {
        "ok": True,
        "player_id": player.player_id,
        "player_name": player.display_name,
        "competition_name": comp.name,
        "competition_slug": comp.slug,
        "run_ends_at": player.ends_at,
        "checkin_interval_s": 60,
        "last_seq": 0,
    }


def derive_slug(name: str, taken: "set[str]") -> str:
    """Slugify a competition name; -2/-3... suffixes on collisions."""
    base = re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")
    if not base:
        base = "competition"
    base = base[:60].rstrip("-") or "competition"
    slug, n = base, 2
    while slug in taken:
        slug = f"{base}-{n}"
        n += 1
    return slug


def create_competition(store: Store, *, slug: str, name: str,
                       scenario_name: str, scenario_version: int,
                       max_players: int, duration_s: int,
                       workshop_pool_code: Optional[str] = None,
                       theme_json: Optional[str] = None,
                       join_instructions: Optional[str] = None,
                       auto_end: bool = False):
    err = validate_slug(slug)
    if err:
        raise ValueError(err)
    if not isinstance(name, str) or not name.strip():
        raise ValueError("Competition name is required.")
    if not isinstance(max_players, int) or isinstance(max_players, bool) or max_players < 1:
        raise ValueError("max_players must be a positive integer.")
    if not isinstance(duration_s, int) or isinstance(duration_s, bool) or duration_s < 60:
        raise ValueError("duration_s must be at least 60 seconds.")
    if store.get_competition_by_slug(slug) is not None:
        raise ValueError("That slug is already in use.")
    # The box folder holds exactly one current version per scenario; running
    # anything else is refused (competitions migrate forward, never back).
    current = scenario_mod.current_box_scenario(scenario_name)
    if current is not None and scenario_version != current[0]:
        raise ValueError(
            f"Scenario {scenario_name} v{scenario_version} is not current "
            f"(engine has v{current[0]}); versions are not migrated in "
            f"place -- discard this draft on its admin page and recreate it "
            f"from the current scenario with 'New competition' on the admin "
            f"console (/admin).")
    if store.get_scenario(scenario_name, scenario_version) is None:
        raise ValueError(
            f"Scenario {scenario_name} v{scenario_version} is not on the "
            f"engine; sync the box folder or upload the record.")
    # The box is on the engine and its rubric is fine; only its pool block
    # failed to expand. Say that -- "no such scenario" sends the operator
    # hunting for a file that is sitting right there, and the real fix is an
    # environment variable or a pools-file entry.
    problem = scenario_mod.pool_problem(scenario_name)
    if problem:
        raise ValueError(
            f"Scenario {scenario_name} cannot start a competition yet: its "
            f"ranked pool block failed to expand ({problem})")
    return store.create_competition(
        slug=slug, name=name.strip(), scenario_name=scenario_name,
        scenario_version=scenario_version, max_players=max_players,
        duration_s=duration_s, workshop_pool_code=workshop_pool_code,
        theme_json=theme_json, join_instructions=join_instructions,
        auto_end=auto_end,
    )


def create_player_with_code(store: Store, comp: CompetitionRecord,
                            display_name: str, server_secret: bytes,
                            ttl_s: int = 1800):
    """Reserve a player slot and mint a one-time join code."""
    err = validate_display_name(display_name)
    if err:
        return None, None, err
    if comp.status != "live" or not comp.join_open:
        return None, None, "This competition is not accepting joins."
    count = store.count_players(comp.id)
    if comp.max_players and count >= comp.max_players:
        return None, None, "This competition is full."
    cleaned = _WS_RE.sub(" ", display_name.strip())
    norm = normalize_name(display_name)
    for _ in range(5):
        code = generate_join_code()
        try:
            player = store.create_player(
                comp.id, cleaned, norm,
                hash_join_code(server_secret, code),
                time.time() + ttl_s, join_code_plain=code,
            )
        except JoinCodeCollision:
            # A 40-bit code collision across concurrent fields. Mint another;
            # this must not surface as "name already taken".
            continue
        if player is None:
            return None, None, "That name is already taken in this competition."
        return player, code, None
    return None, None, "Could not allocate a join code; try again."
