"""Ranked competition domain logic: competitions, players, runs, join.

All state lives in engine.store. This module is pure business logic except
for the signed /join verification and the leaderboard shaping used by the
HTTP layer.
"""
import base64
import hashlib
import hmac
import html
import re
import secrets
import time
from typing import Optional

from common import canon
from common.crypto import signing
from common.schema import SCHEMA_VERSION
from engine import scenario as scenario_mod
from engine import verify_gate
from engine.store import CompetitionRecord, PlayerRecord, Store

# Unambiguous alphabet (no 0/O/1/I/L) for codes that get typed off a screen.
_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
_CODE_LEN = 8
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


def _remaining(player: PlayerRecord, now: float) -> int:
    if player.ends_at is None:
        return 0
    return max(0, int(player.ends_at - now))


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
    tie-breaks. A player whose clock has run out is treated as finished even
    if no check-in has persisted that status yet.
    """
    players = [p for p in store.list_players(comp.id)
               if p.status in ("running", "finished")]
    scored = []
    for p in players:
        status = p.status
        if status == "running" and p.ends_at is not None and now >= p.ends_at:
            status = "finished"
        score = store.get_score(p.box_id) if p.box_id else None
        total = score["total"] if score else 0
        scored.append((p, status, score, total))
    scored.sort(key=lambda item: (
        -item[3], item[0].started_at or 0, item[0].player_id))
    return scored


def rank_for_player(store: Store, comp: Optional[CompetitionRecord],
                    player: Optional[PlayerRecord],
                    now: Optional[float] = None) -> "tuple[Optional[int], Optional[int]]":
    """(position, total players) for ``player`` on the live scoreboard.

    Returns (None, None) for a box that is not attached to a competition, and
    (None, total) if the player is no longer on the board (e.g. removed).
    The identity comparison is by player_id, not object identity.
    """
    if comp is None or player is None:
        return None, None
    now = time.time() if now is None else now
    scored = _scored_players(store, comp, now)
    for idx, (row_player, _status, _score, _total) in enumerate(scored, start=1):
        if row_player.player_id == player.player_id:
            return idx, len(scored)
    return None, len(scored)


def leaderboard_payload(store: Store, comp: CompetitionRecord,
                        now: Optional[float] = None) -> dict:
    now = time.time() if now is None else now
    rows = []
    for p, status, score, total in _scored_players(store, comp, now):
        rows.append({
            "player_id": p.player_id,
            "name": p.display_name,
            "status": status,
            "total": total,
            "hardening_points": score["hardening_points"] if score else 0,
            "service_points": score["service_points"] if score else 0,
            "started_at": p.started_at,
            "ends_at": p.ends_at,
            "remaining_s": _remaining(p, now) if status == "running" else 0,
            "last_checkin": score["updated_at"] if score else None,
            "services": _service_rows(store, comp, p.box_id),
            "box_bound": bool(p.box_id),
        })
    for idx, row in enumerate(rows, start=1):
        row["rank"] = idx
    return {
        "competition": public_competition_payload(store, comp, now=now),
        "leaderboard": rows,
        "generated_at": now,
    }


def public_competition_payload(store: Store, comp: CompetitionRecord,
                               now: Optional[float] = None) -> dict:
    now = time.time() if now is None else now
    count = store.count_players(comp.id)
    theme = {}
    if comp.theme_json:
        import json
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
        "max_players": comp.max_players,
        "player_count": count,
        "duration_s": comp.duration_s,
        "started_at": comp.started_at,
        "ended_at": comp.ended_at,
        "theme": theme,
        "join_instructions": comp.join_instructions,
        "can_join": (comp.status == "live" and comp.join_open
                     and (comp.max_players <= 0 or count < comp.max_players)),
    }


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
                    details_json='{"box_id": %s}' % __import__("json").dumps(body["box_id"]))
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
                       join_instructions: Optional[str] = None):
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
    if store.get_scenario(scenario_name, scenario_version) is None:
        raise ValueError("Upload that scenario record to the engine first.")
    return store.create_competition(
        slug=slug, name=name.strip(), scenario_name=scenario_name,
        scenario_version=scenario_version, max_players=max_players,
        duration_s=duration_s, workshop_pool_code=workshop_pool_code,
        theme_json=theme_json, join_instructions=join_instructions,
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
    code = generate_join_code()
    player = store.create_player(
        comp.id, _WS_RE.sub(" ", display_name.strip()),
        normalize_name(display_name), hash_join_code(server_secret, code),
        time.time() + ttl_s, join_code_plain=code,
    )
    if player is None:
        return None, None, "That name is already taken in this competition."
    return player, code, None
