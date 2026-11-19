"""Shared fixture for debrief tests: one small synthetic engine db.

Built with the engine's own schema (plus the store's runtime migrations):
one competition, three teams, check-ins with bundles, one SLA row and one
adversary event, so every layer above has consistent facts to consume.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from engine.store_schema import SCHEMA

TEAM_ROWS = [
    (1, "rosemoor-1", "b0cfa10c-1", 1, 1_700_000_000.0),
    (2, "rosemoor-2", "b0cfa10c-2", 2, 1_700_000_100.0),
    (3, "harborline-1", "b0cfa10c-3", 3, 1_700_000_200.0),
]


def make_db(tmp_path: Path) -> Path:
    """One engine db with the fixture rows; the engine schema verbatim."""
    db_path = tmp_path / "engine.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    conn.executescript(_SCORE_COLUMNS)

    conn.execute(
        "INSERT INTO competitions (id, slug, name, scenario_name,"
        " scenario_version, status, join_open, max_players, duration_s,"
        " created_at, started_at, ended_at)"
        " VALUES ('c1', 'spring-range', 'Spring Range 2025',"
        " 'Broadneck Post', 1, 'ended', 1, 8, 7200,"
        " 1700000000, 1700000000, 1700007200)"
    )
    for player_id, display, box, seq, received in TEAM_ROWS:
        conn.execute(
            "INSERT INTO players (player_id, competition_id, display_name,"
            " display_name_norm, status, joined_at, started_at, ends_at,"
            " box_id)"
            " VALUES (?, 'c1', ?, ?, 'finished', 1700000000, ?, ?, ?)",
            (str(player_id), display, display.lower(),
             received, received + 7200, box),
        )
        conn.execute(
            "INSERT INTO scores (box_id, scenario_name, total, updated_at,"
            " first_scored_at, hardening_points, service_points,"
            " ungraded_count, score_json)"
            " VALUES (?, 'Broadneck Post', 82.0, ?, ?, 70, 12, 0, ?)",
            (box, received + 100, received + 30, _SCORE_JSON),
        )
        conn.execute(
            "INSERT INTO checkins (box_id, seq, received_at, bundle_json)"
            " VALUES (?, ?, ?, ?)",
            (box, seq, received, _BUNDLE_JSON),
        )
    conn.execute(
        "INSERT INTO sla_state (box_id, check_id, state, consec_ok,"
        " consec_fail, last_credited_at, accrued_points, history_json)"
        " VALUES ('b0cfa10c-1', 'svc_web', 'UP', 2, 0, 1700000000,"
        " 3, '[\"UP\",\"UP\"]')"
    )
    conn.execute(
        "INSERT INTO adversary_log (box_id, event_id, action, issued_at,"
        " params_json, affects_check, restored_at)"
        " VALUES ('b0cfa10c-2', 'kill-web', 'kill_service', 1700000300,"
        " '{\"service\": \"huitz-demo-web\"}', 'svc_web', 1700000400)"
    )
    conn.commit()
    conn.close()
    return db_path


def _migrate(conn: sqlite3.Connection) -> None:
    """Integration helper: one competition's debrief digest needs a scores
    table beyond what SCHEMA ships, so sync it in place."""
    conn.executescript(_SCORE_COLUMNS)


_SCORE_COLUMNS = """
ALTER TABLE scores ADD COLUMN hardening_points INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scores ADD COLUMN service_points INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scores ADD COLUMN ungraded_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scores ADD COLUMN score_json TEXT;
"""

_SCORE_JSON = (
    '{"results": [{"check_id": "banner", "passed": true,'
    ' "awarded_points": 10}, {"check_id": "recipe_private",'
    ' "passed": false, "awarded_points": 0}],'
    ' "sla_status": [{"check_id": "svc_web",'
    ' "state": "UP", "accrued_points": 3}]}'
)
_BUNDLE_JSON = '{"evidence": [{"check_id": "banner", "status": "ok"}]}'
