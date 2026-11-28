"""Facts layer for the debrief tool. Read-only over the engine's SQLite db.

The debrief's job is a *presentation* of the run: every number here is a
fact the engine already scored and stored, re-read by this module in one
pass per team. Nothing invents a fact, nothing extrapolates from one.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Optional

from common.evaluator import evaluate
from common.schema import Evidence

def _connect_readonly(db_path: Path) -> sqlite3.Connection:
    uri = f"file:{db_path}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _competitions(conn: sqlite3.Connection,
                  slug: Optional[str] = None) -> list[dict]:
    rows = [_row_dict(r) for r in conn.execute("SELECT * FROM competitions")]
    if not rows:
        # A removed competition deletes its row but keeps boxes/scores as
        # history (§21): rebuild the context from what survived.
        rows = _archived_competitions(conn)
    if slug is not None:
        rows = [c for c in rows if c.get("slug") == slug]
    rows.sort(key=lambda c: c.get("created_at") or 0, reverse=True)
    return rows


def _archived_competitions(conn: sqlite3.Connection) -> list[dict]:
    """One pseudo-competition per distinct competition_id still attached to
    a box. The competition row is gone (removed competitions delete it),
    but the append-only audit log survived it: competition_delete carries
    the original slug, so the report can carry the run's real name."""
    names = _archived_audit_names(conn)
    out: dict[str, dict] = {}
    for row in conn.execute(
        "SELECT DISTINCT competition_id FROM boxes WHERE competition_id"
        " IS NOT NULL"
    ):
        comp_id = row["competition_id"]
        boxes = conn.execute(
            "SELECT scenario_name, scenario_version, MIN(t0) AS t0,"
            " MAX(t0) AS last_t0 FROM boxes WHERE competition_id = ?",
            (comp_id,),
        ).fetchall()
        box = dict(boxes[0]) if boxes else {}
        slug = names["slugs"].get(comp_id) or f"archived-{comp_id[:8]}"
        out[comp_id] = {
            "id": comp_id,
            "slug": slug,
            "name": slug,
            "scenario_name": box.get("scenario_name"),
            "scenario_version": box.get("scenario_version"),
            "max_players": 0,
            "status": "ended",
            "join_open": 0,
            "duration_s": 0,
            "workshop_pool_code": None,
            "workshop_pool_name": None,
            "created_at": box.get("t0"),
            "started_at": box.get("t0"),
            "ended_at": box.get("last_t0"),
        }
    return list(out.values())


def _archived_audit_names(conn: sqlite3.Connection) -> dict:
    """Recover what the audit log outlived: per-competition slugs (from
    competition_delete details) and per-player display names (from
    join_reserved details). Both are facts the engine recorded at the
    time; nothing here is inferred."""
    slugs: dict[str, str] = {}
    names: dict[tuple, str] = {}
    for row in conn.execute(
        "SELECT competition_id, player_id, action, details_json"
        " FROM audit_log WHERE action IN"
        " ('competition_delete', 'join_reserved')"
    ):
        details = _json(row["details_json"])
        if row["action"] == "competition_delete":
            slug = details.get("slug")
            if row["competition_id"] and isinstance(slug, str) and slug:
                slugs[row["competition_id"]] = slug
        elif row["action"] == "join_reserved":
            name = details.get("name")
            key = (row["competition_id"], row["player_id"])
            if all(key) and isinstance(name, str) and name:
                names[key] = name
    return {"slugs": slugs, "names": names}


def _players_for(conn: sqlite3.Connection, competition_id: str) -> list[dict]:
    rows = [_row_dict(r) for r in conn.execute(
        "SELECT player_id, competition_id, display_name, display_name_norm,"
        " status, joined_at, started_at, ends_at, finished_at, box_id"
        " FROM players WHERE competition_id = ?"
        " ORDER BY joined_at, player_id",
        (competition_id,),
    )]
    if not rows:
        rows = _archived_players(conn, competition_id)
    rows.sort(key=lambda p: (p.get("joined_at") or 0, p.get("player_id")))
    return rows


def _archived_players(conn: sqlite3.Connection,
                      competition_id: str) -> list[dict]:
    """Player facts rebuilt from the boxes that remain. Display names come
    from the audit log's join_reserved entries (the name the player chose
    at join time); the box id prefix stands in when the audit row is gone
    too."""
    names = _archived_audit_names(conn)["names"]
    boxes = conn.execute(
        "SELECT box_id, player_id, t0, competition_id FROM boxes"
        " WHERE competition_id = ? ORDER BY t0, box_id",
        (competition_id,),
    ).fetchall()
    out = []
    for box in boxes:
        box_id = box["box_id"]
        player_id = box["player_id"] or box_id
        started = box["t0"]
        display = names.get((competition_id, player_id)) or f"box {box_id[:8]}"
        last = conn.execute(
            "SELECT MAX(received_at) AS last FROM checkins WHERE box_id = ?",
            (box_id,),
        ).fetchone()
        out.append({
            "player_id": player_id,
            "competition_id": competition_id,
            "display_name": display,
            "display_name_norm": display.lower(),
            "status": "archived",
            "joined_at": started,
            "started_at": started,
            "ends_at": None,
            "finished_at": dict(last)["last"] if last else None,
            "box_id": box_id,
        })
    return out


def _score_for(conn: sqlite3.Connection, box_id: str) -> Optional[dict]:
    columns = {r["name"] for r in conn.execute(
        "SELECT name FROM pragma_table_info('scores')")}
    selected = ("box_id, total, updated_at, first_scored_at,"
                " hardening_points, service_points, score_json")
    if "forensics_points" in columns:
        selected = selected.replace(
            "hardening_points,",
            "hardening_points, forensics_points,")
    if "ungraded_count" in columns:
        selected += ", ungraded_count"
    row = conn.execute(
        f"SELECT {selected} FROM scores WHERE box_id = ?", (box_id,)
    ).fetchone()
    if row is None:
        return None
    data = _row_dict(row)
    data.setdefault("ungraded_count", 0)
    data["score_json"] = _json(data.pop("score_json"))
    return data


def _checkins_for(conn: sqlite3.Connection, box_id: str,
                  limit: int = 2000) -> list[dict]:
    rows = conn.execute(
        "SELECT box_id, seq, received_at, bundle_json FROM checkins"
        " WHERE box_id = ? ORDER BY seq LIMIT ?",
        (box_id, limit),
    ).fetchall()
    out = []
    for row in rows:
        data = _row_dict(row)
        data["bundle"] = _json(data.pop("bundle_json"))
        out.append(data)
    return out


def _sla_state_for(conn: sqlite3.Connection, box_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT box_id, check_id, state, consec_ok, consec_fail,"
        " last_credited_at, accrued_points, history_json"
        " FROM sla_state WHERE box_id = ?",
        (box_id,),
    ).fetchall()
    return [_row_dict(r) for r in rows]


def _adversary_log_for(conn, box_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT box_id, event_id, action, issued_at, params_json,"
        " affects_check, restored_at"
        " FROM adversary_log WHERE box_id = ?",
        (box_id,),
    ).fetchall()
    return [_row_dict(r) for r in rows]


def _row_dict(row: sqlite3.Row) -> dict:
    return {k: row[k] for k in row.keys()}


def _json(raw: Optional[str]) -> dict:
    try:
        return json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return {}




def build_digest(db_path: Path,
                 competition_slug: Optional[str] = None) -> list[dict]:
    """Recompute debrief facts from the engine's store, one pass per team.

    Read-only; every number comes from the db — nothing invented or averaged."""
    conn = _connect_readonly(db_path)
    try:
        competitions = _competitions(conn)
        if competition_slug is not None:
            competitions = [
                comp for comp in competitions
                if comp.get("slug") == competition_slug
            ]
        if not competitions:
            raise ValueError(f"no competitions found in {db_path}")
        digests = []
        for comp in competitions:
            for player in _players_for(conn, comp["id"]):
                # a player still holding a reservation but never bound to a
                # box has no run to debrief; skip, don't render an empty one
                if not player.get("box_id"):
                    continue
                digests.append(_team_facts(conn, player, comp))
        return digests
    finally:
        conn.close()


def _member_names(conn, player_id: Optional[str]) -> list[str]:
    """The seat's named roster (team_members), oldest first. Empty when the
    seat has none or the store predates the table -- the debrief reads
    stores of any vintage, read-only."""
    if not player_id:
        return []
    cols = {r["name"] for r in conn.execute(
        "SELECT name FROM pragma_table_info('team_members')")}
    if "handle" not in cols:
        return []
    return [r["handle"] for r in conn.execute(
        "SELECT handle FROM team_members WHERE player_id = ?"
        " ORDER BY added_at ASC", (player_id,))]


def _team_facts(conn, player: dict, comp: dict,
                maxes_cache: Optional[dict] = None) -> dict:
    """One team's debrief facts, from the store's own records."""
    box_id = player.get("box_id")
    score = _score_for(conn, box_id) if box_id else {}
    checkins = _checkins_for(conn, box_id) if box_id else []
    sla_rows = _sla_state_for(conn, box_id) if box_id else []
    adversary = _adversary_log_for(conn, box_id) if box_id else []

    if maxes_cache is None:
        maxes_cache = {}
    key = (comp.get("scenario_name"), comp.get("scenario_version"))
    if key not in maxes_cache:
        maxes_cache[key] = _rubric_maxes(conn, key[0], key[1])
    maxes = maxes_cache[key]

    score_total = (score.get("score_json") or {}).get("results", [])
    run_span = _run_span(checkins)
    return {
        "competition": dict(comp),
        "team": {
            "display_name": player.get("display_name"),
            "status": player.get("status"),
            "members": _member_names(conn, player.get("player_id")),
            "run_minutes": run_span["minutes"],
            "checkin_count": run_span["checkins"],
            "ungraded_count": score.get("ungraded_count", 0),
            "score": {
                "total": score.get("total", 0),
                "hardening_points": score.get("hardening_points", 0),
                "service_points": score.get("service_points", 0),
                "forensics_points": score.get("forensics_points", 0),
                "max_total": score.get("total", 0) and _max_total(maxes),
            },
            "checks": _check_facts(score_total, maxes),
            "services": _service_facts(sla_rows),
            "incidents": _incident_facts(adversary),
        },
        "feedback_pool": _feedback_pool(score_total, adversary, maxes),
    }


def _rubric_maxes(conn, scenario_name: Optional[str],
                  version: Optional[int]) -> dict:
    """check_id -> max points, from the stored scenario record.

    Empty when the record is gone (a removed competition's version is
    pruned once a newer one syncs): callers then report counts, not
    points, and say so."""
    if not scenario_name or version is None:
        return {}
    row = conn.execute(
        "SELECT rubric_json FROM scenarios"
        " WHERE scenario_name = ? AND scenario_version = ?",
        (scenario_name, version),
    ).fetchone()
    if row is None:
        return {}
    maxes = {}
    for entry in _json(row["rubric_json"]).get("entries") or []:
        cid = entry.get("check_id")
        points = entry.get("points", 0)
        if cid and isinstance(points, int) and points > 0:
            maxes[cid] = points
    return maxes


def _max_total(maxes: dict) -> int:
    return sum(maxes.values())


def _run_span(checkins: list[dict]) -> dict:
    """How long the box actually reported for, from its own check-ins."""
    stamps = [c.get("received_at") for c in checkins if c.get("received_at")]
    if not stamps:
        return {"minutes": 0, "checkins": 0}
    return {
        "minutes": round((max(stamps) - min(stamps)) / 60, 1),
        "checkins": len(stamps),
    }


def _check_facts(results: list[dict], maxes: dict) -> list[dict]:
    """Per-check rows carrying the engine's own verdict (absent = never
    scored); ``max_points`` only while the run's rubric is still stored."""
    rows = []
    for entry in results:
        cid = entry.get("check_id")
        rows.append({
            "id": cid,
            "title": cid,
            "category": entry.get("category"),
            "points": entry.get("awarded_points", 0),
            "max_points": maxes.get(cid),
            "solved": bool(entry.get("passed")),
        })
    return rows


def _service_facts(sla_rows: list[dict]) -> list[dict]:
    """Per-service facts, straight from the SLA ledger (authoritative).

    Health is the engine's rubric-in-hand judgement — report its record,
    never re-derive from raw evidence. No run-long uptime %: only the last
    SLA_HISTORY_MAX ticks are retained."""
    rows = []
    for rec in sla_rows:
        rows.append({
            "check_id": rec.get("check_id"),
            "state": rec.get("state"),
            "accrued_points": rec.get("accrued_points", 0),
            "recent_ticks": _ticks(rec.get("history_json")),
        })
    rows.sort(key=lambda r: r.get("check_id") or "")
    return rows


def _ticks(raw) -> list:
    if isinstance(raw, list):
        return [str(t) for t in raw]
    try:
        return [str(t) for t in json.loads(raw or "[]")]
    except (TypeError, json.JSONDecodeError):
        return []


def _incident_facts(adversary: list[dict]) -> list[dict]:
    """Incidents, or the runs the team handled."""
    return [
        {
            "event_id": row.get("event_id"),
            "action": row.get("action"),
            "restored": bool(row.get("restored_at")),
        }
        for row in adversary
    ]


def _feedback_pool(results: list[dict], adversary: list[dict],
                   maxes: dict) -> list[dict]:
    """What an LLM narrates from: misses first, ordered by importance.

    narrate() only ever picks among these ids — never an unlisted check;
    points_lost carries the max only while the rubric is still stored."""
    pool = []
    for entry in results:
        if entry.get("passed"):
            continue
        pool.append({
            "id": entry.get("check_id"),
            "kind": "hardening",
            "title": entry.get("check_id"),
            "points_lost": maxes.get(entry.get("check_id")),
        })
    for row in adversary:
        pool.append({
            "id": row.get("event_id"),
            "kind": "incident",
            "title": row.get("event_id"),
            "points_lost": 0,
        })
    return pool
