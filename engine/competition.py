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
                          Store, normalize_name)

#: unambiguous alphabet (no 0/O/1/I/L) — codes get typed off a screen.
_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
_CODE_LEN = 4
_NAME_MAX = 40
_MEMBER_MAX = 60
_SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
_WS_RE = re.compile(r"\s+")

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


# --- teams (v1.2) ---------------------------------------------------------

def validate_member_handle(raw) -> Optional[str]:
    """A teammate handle: one line, capped, empty rejected. None = invalid."""
    cleaned = _WS_RE.sub(" ", (raw or "").strip())
    if not cleaned or len(cleaned) > _MEMBER_MAX:
        return None
    return cleaned


def team_roster_full(store: Store, comp: CompetitionRecord,
                     player: PlayerRecord) -> bool:
    """True when the seat's named roster has hit the competition's
    max_team_members cap (self-serve joins and hand adds share it)."""
    cap = max(1, comp.max_team_members)
    return len(store.list_team_members(player.player_id)) >= cap


def generate_team_token() -> str:
    """URL-safe shared-link secret. Unlike the typed join code this is never
    read off a screen: it lives only in a link, so it carries full entropy."""
    return secrets.token_urlsafe(16)


def hash_team_token(server_secret: bytes, token: str) -> str:
    """Domain-separated so a join-code hash can never double as a token hash."""
    return hmac.new(server_secret, b"huitz-team:" + token.encode("utf-8"),
                    hashlib.sha256).hexdigest()


def rotate_team_token(store: Store, player: PlayerRecord,
                      server_secret: bytes) -> Optional[str]:
    """Mint a fresh team link; the old one stops resolving. Returns the plain
    token to show once (the dashboard's Team card shows the live one)."""
    for _ in range(5):
        token = generate_team_token()
        try:
            store.update_player(
                player.player_id,
                team_token_hash=hash_team_token(server_secret, token),
                team_token_plain=token,
            )
        except JoinCodeCollision:
            continue
        return token
    return None


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
    return _service_rows_for(store, comp, box_id,
                             comp.scenario_name, comp.scenario_version)


def _service_rows_for(store: Store, comp: CompetitionRecord,
                      box_id: Optional[str], scenario_name: str,
                      scenario_version: int) -> list:
    services = scenario_mod.load_services(store, scenario_name,
                                          scenario_version)
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
            "history": list(rec.history) if rec is not None else [],
        })
    return out


def service_rows(store: Store, comp: CompetitionRecord,
                 box_id: Optional[str] = None,
                 player: Optional[PlayerRecord] = None) -> list:
    """Public service rows for a player, including before their box joins.

    An unbound slot still shows every scored service (state PENDING, empty
    history) so the dashboard's uptime strip has real names from the start.
    With ``player`` (multi-box seat) the strip covers the whole lineup;
    without it, behavior is the single-box path it always was.
    """
    if player is not None:
        boxes = _seat_boxes(store, comp, player)
        if len(store.get_competition_scenarios(comp.id)) > 1:
            return _seat_service_rows(store, comp, boxes, player)
        box_id = player.box_id
    return _service_rows(store, comp, box_id)


def seat_boxes_view(store: Store, comp: CompetitionRecord, p) -> list:
    """Per-lineup-entry box state for the player pages:
    {scenario_name, box_id, bound, claim_url, claim_uid, pending, error}.
    Empty for a single-scenario competition -- those pages keep rendering
    their exact pre-v1.2 VM card from the players row.
    """
    lineup = store.get_competition_scenarios(comp.id)
    if len(lineup) <= 1:
        return []
    slots = {s.scenario_name: s for s in store.list_run_slots(p.player_id)}
    out = []
    for s_name, _ver in lineup:
        s = slots.get(s_name)
        out.append({
            "scenario_name": s_name,
            "box_id": s.box_id if s else None,
            "bound": bool(s.box_id) if s else False,
            "claim_url": (s.claim_url if s else None),
            "claim_uid": (s.claim_uid if s else None),
            "pending": bool(s.claim_ticket) if s else False,
            "error": (s.claim_error if s else None),
            "released_at": (s.box_released_at if s else None),
        })
    return out


def _seat_boxes(store: Store, comp: CompetitionRecord,
                p) -> list:
    """The seat's bound boxes as (scenario_name, scenario_version, box_id),
    in lineup order. A single-box seat has exactly its players.box_id mirror
    (the migration guarantees one slot per player, and the mirror tracks the
    position-0 slot), so every aggregation downstream collapses to precisely
    the pre-multi-box numbers.
    """
    bound = [(s.scenario_name, s.scenario_version, s.box_id)
             for s in store.list_run_slots(p.player_id) if s.box_id]
    if not bound and p.box_id:
        bound = [(comp.scenario_name, comp.scenario_version, p.box_id)]
    return bound


def _aggregate_scores(store: Store, boxes: list):
    """Sum the seat's per-box score rows into the one-row shape the board
    reads. None (never scored) is preserved for a seat with no scored box."""
    scores = [s for s in (store.get_score(b_id) for _n, _v, b_id in boxes)
              if s is not None]
    if not scores:
        return None, 0
    agg = {
        "total": sum(s["total"] for s in scores),
        "hardening_points": sum(s["hardening_points"] for s in scores),
        "service_points": sum(s["service_points"] for s in scores),
        "forensics_points": sum(s.get("forensics_points", 0) for s in scores),
        "ungraded_count": sum(s.get("ungraded_count", 0) for s in scores),
        "updated_at": max(s["updated_at"] for s in scores),
        "parts": scores,
    }
    return agg, agg["total"]


def _seat_service_rows(store: Store, comp: CompetitionRecord, boxes: list,
                       p) -> list:
    """The seat's scored-service rows across the lineup. With one scenario
    this is exactly _service_rows on the seat's box (the old path, including
    its PENDING-before-join behavior); multi-box rows are concatenated in
    lineup order and each carries a "scenario" label.
    """
    lineup = store.get_competition_scenarios(comp.id)
    if len(lineup) <= 1:
        return _service_rows(store, comp, p.box_id)
    by_scenario = {b[0]: b[2] for b in boxes}
    out = []
    for s_name, s_ver in lineup:
        box_id = by_scenario.get(s_name)
        rows = _service_rows_for(store, comp, box_id, s_name, s_ver)
        for r in rows:
            r["scenario"] = s_name
        out.extend(rows)
    return out


def _scored_players(store: Store, comp: CompetitionRecord, now: float) -> list:
    """(player, effective status, score, total) in scoreboard order.

    One ordering function for the public board and the per-box rank shown in
    the ranked report: totals first, then the stable started_at/player_id
    ordering. Equal totals share a rank (standard competition ranking:
    1, 2, 2, 4); the ordering keys only decide display order. A player whose
    clock has run out is treated as finished even if no check-in has
    persisted that status yet.

    ``score`` is the seat's aggregate across its bound boxes (a single score
    row for single-box competitions, with the same keys).
    """
    # A player is on the board only once a box is bound: a slot that has not
    # connected yet must never look like a zero-point competitor.
    players = []
    for p in store.list_players(comp.id):
        if p.status not in ("running", "finished"):
            continue
        boxes = _seat_boxes(store, comp, p)
        if boxes:
            players.append((p, boxes))
    scored = []
    for p, boxes in players:
        status = p.status
        # Lazy finish: past the effective end (run clock or a live
        # competition's scheduled-end wall time) the run is over even before
        # the sweeper persists it — the clock is the truth, the row catches up.
        effective_end = effective_run_end(comp, p)
        if status == "running" and effective_end is not None and now >= effective_end:
            status = "finished"
        score, total = _aggregate_scores(store, boxes)
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
    """One leaderboard row, shared by the public payload and player_board_row.

    ``score`` is the seat's aggregate (see _aggregate_scores); its "parts"
    carry the per-box rows, which only multi-box competitions surface (as a
    "boxes" breakdown) so a single-box row keeps its exact v1.1 shape.
    """
    boxes = _seat_boxes(store, comp, p)
    row = {
        "player_id": p.player_id,
        "name": p.display_name,
        "status": status,
        "total": total,
        "hardening_points": score["hardening_points"] if score else 0,
        "service_points": score["service_points"] if score else 0,
        "forensics_points": (score.get("forensics_points", 0)
                             if score else 0),
        "ungraded_count": (score.get("ungraded_count", 0) if score else 0),
        "started_at": p.started_at,
        "ends_at": p.ends_at,
        "remaining_s": (_remaining_from(effective_run_end(comp, p), now)
                        if status == "running" else 0),
        "last_checkin": score["updated_at"] if score else None,
        "services": _seat_service_rows(store, comp, boxes, p),
        "box_bound": bool(boxes),
    }
    if len(store.get_competition_scenarios(comp.id)) > 1:
        # Stable shape for multi-lineup boards: every seat gets the per-box
        # breakdown (a partially bound seat simply lists fewer boxes).
        row["boxes"] = [
            {"scenario_name": s_name, "box_id": b_id,
             "total": (store.get_score(b_id) or {}).get("total", 0)}
            for s_name, _v, b_id in boxes]
    return row


def player_board_row(store: Store, comp: CompetitionRecord, player,
                     now: Optional[float] = None) -> Optional[dict]:
    """The leaderboard row for one player, even when the public board is hidden.

    A hidden board withholds everyone else's standings, but a player's own
    score and rank are their own data (the on-box report shows them too).
    Returns None with no scored check-in; adds ``board_total`` so the rank
    line can say "of N" without the public rows.
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
        # v1.2: 1 for every competition that predates lineups; >1 for a
        # multi-box competition (pages use it to pick their rendering).
        "box_count": max(1, len(store.get_competition_scenarios(comp.id))),
        "started_at": comp.started_at,
        "ended_at": comp.ended_at,
        "scheduled_end_at": getattr(comp, "scheduled_end_at", None),
        "theme": theme,
        "join_instructions": comp.join_instructions,
        "can_join": (comp.status == "live" and comp.join_open
                     and (comp.max_players <= 0 or count < comp.max_players)),
    }


def extend_runs(store: Store, comp: CompetitionRecord, seconds: int, *,
                now: Optional[float] = None) -> dict:
    """Grant overtime to a live competition's runs (admin action).

    Scoring runs on the engine receipt clock against stored ``ends_at``, so
    this only moves deadlines, never box clocks: running clocks slide by
    ``seconds``; a run frozen by expiry restarts at ``now + seconds`` on an
    even footing; released boxes (no agent left) and never-claimed invited
    slots are skipped; removed/disqualified are never touched. Returns a
    report the admin API forwards verbatim; the caller audits it.
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
            # invited has no clock yet; running-without-ends_at cannot happen,
            # but leave anything unexplainable untouched and say so. Removed
            # and disqualified slots fall through, never touched, by design.
            skipped.append({"name": p.display_name, "status": p.status})
    return {"minutes": seconds // 60, "seconds": seconds,
            "extended": extended, "resumed": resumed, "skipped": skipped}


class ExtendRefused(Exception):
    """The competition is not in a state that accepts an extension."""


#: sanity bound on a scheduled end: far enough for any multi-day event,
#: tight enough to catch a fat-fingered year.
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

    Runs once per sweep tick, independent of the VM-claim sweep: a scheduled
    end must fire even with no portal configured. Ending is the exact
    admin-End path; ``cleanup`` is the caller-injected pool teardown (claims
    would import circularly; ``None`` defers VM work one tick). Best effort
    per competition — one failure never skips the others.
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
                       auto_end: bool = False,
                       max_team_members: int = 10,
                       scenarios: Optional[list] = None):
    err = validate_slug(slug)
    if err:
        raise ValueError(err)
    if not isinstance(name, str) or not name.strip():
        raise ValueError("Competition name is required.")
    if not isinstance(max_players, int) or isinstance(max_players, bool) or max_players < 1:
        raise ValueError("max_players must be a positive integer.")
    if (not isinstance(max_team_members, int) or isinstance(max_team_members, bool)
            or max_team_members < 1):
        raise ValueError("max_team_members must be a positive integer.")
    if not isinstance(duration_s, int) or isinstance(duration_s, bool) or duration_s < 60:
        raise ValueError("duration_s must be at least 60 seconds.")
    if store.get_competition_by_slug(slug) is not None:
        raise ValueError("That slug is already in use.")
    # The lineup is one entry (the legacy pair) or an explicit ordered list;
    # the competition-level scenario_* fields mirror entry 0 in both cases.
    lineup = [(scenario_name, int(scenario_version))] if scenarios is None \
        else [(n, int(v)) for n, v in scenarios]
    if len(set(n for n, _ in lineup)) != len(lineup):
        raise ValueError("A lineup scenario may appear only once.")
    for entry_name, entry_version in lineup:
        # The box folder holds exactly one current version per scenario;
        # running anything else is refused (competitions migrate forward,
        # never back) -- enforced per lineup entry.
        current = scenario_mod.current_box_scenario(entry_name)
        if current is not None and entry_version != current[0]:
            raise ValueError(
                f"Scenario {entry_name} v{entry_version} is not current "
                f"(engine has v{current[0]}); versions are not migrated in "
                f"place -- discard this draft on its admin page and recreate it "
                f"from the current scenario with 'New competition' on the admin "
                f"console (/admin).")
        if store.get_scenario(entry_name, entry_version) is None:
            raise ValueError(
                f"Scenario {entry_name} v{entry_version} is not on the "
                f"engine; sync the box folder or upload the record.")
        # The box is on the engine and its rubric is fine; only its pool
        # block failed to expand. Say that -- "no such scenario" sends the
        # operator hunting for a file that is sitting right there, and the
        # real fix is an environment variable or a pools-file entry.
        problem = scenario_mod.pool_problem(entry_name)
        if problem:
            raise ValueError(
                f"Scenario {entry_name} cannot start a competition yet: its "
                f"ranked pool block failed to expand ({problem})")
    return store.create_competition(
        slug=slug, name=name.strip(), scenario_name=lineup[0][0],
        scenario_version=lineup[0][1], max_players=max_players,
        duration_s=duration_s, workshop_pool_code=workshop_pool_code,
        theme_json=theme_json, join_instructions=join_instructions,
        auto_end=auto_end, max_team_members=max_team_members, scenarios=lineup,
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
            # A code collision across concurrent fields: mint another — this
            # must not surface as "name already taken".
            continue
        if player is None:
            return None, None, "That name is already taken in this competition."
        # One claim/bind slot per lineup entry, created with the seat so the
        # sweeper can work each box independently (a single-scenario
        # competition -- every seat until v1.2 -- gets exactly one, mirroring
        # the player row).
        lineup = store.get_competition_scenarios(comp.id)
        if not lineup:
            lineup = [(comp.scenario_name, comp.scenario_version)]
        store.create_run_slots(player.player_id, comp.id, lineup)
        # The seat also gets its shareable team link now, so a joining captain
        # can hand teammates access before the box even finishes binding.
        if rotate_team_token(store, player, server_secret) is None:
            store.remove_player(player.player_id)
            return None, None, "Could not allocate a team link; try again."
        return store.get_player(player.player_id), code, None
    return None, None, "Could not allocate a join code; try again."
