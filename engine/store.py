"""SQLite-backed storage. See architecture.md §11.2.

FROZEN — the Store class and record dataclasses below are the contract every
other engine/ module (enrollment.py, checkin.py, sla.py, adversary_oracle.py,
leaderboard.py) is built against. They only need these signatures, not this
file's implementation, so all of engine/ can be built in parallel.

PHASE 1 TASK: implement every method body against a sqlite3 schema covering
the tables in §11.2: boxes, enrollment_tokens, checkins, sla_state, scores,
adversary_log. Do not change method signatures.
"""
import json
import sqlite3
import threading
from dataclasses import dataclass
from typing import Optional


@dataclass
class BoxRecord:
    box_id: str
    public_key: str
    scenario_name: str
    enrolled_at: float
    last_seq: int
    last_boot_id: Optional[str]
    t0: Optional[float]


@dataclass
class SlaStateRecord:
    box_id: str
    check_id: str
    state: str  # "UP" | "DOWN"
    consec_ok: int
    consec_fail: int
    last_credited_at: float
    accrued_points: int


@dataclass
class ScoreRow:
    box_id: str
    scenario_name: str
    total: int
    updated_at: float


_SCHEMA = """
CREATE TABLE IF NOT EXISTS boxes (
    box_id TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,
    scenario_name TEXT NOT NULL,
    enrolled_at REAL NOT NULL,
    last_seq INTEGER NOT NULL,
    last_boot_id TEXT,
    t0 REAL
);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
    token TEXT PRIMARY KEY,
    scenario_name TEXT NOT NULL,
    expires_at REAL NOT NULL,
    consumed_at REAL
);

CREATE TABLE IF NOT EXISTS checkins (
    box_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    received_at REAL NOT NULL,
    bundle_json TEXT NOT NULL,
    UNIQUE(box_id, seq)
);

CREATE TABLE IF NOT EXISTS sla_state (
    box_id TEXT NOT NULL,
    check_id TEXT NOT NULL,
    state TEXT NOT NULL,
    consec_ok INTEGER NOT NULL,
    consec_fail INTEGER NOT NULL,
    last_credited_at REAL NOT NULL,
    accrued_points INTEGER NOT NULL,
    PRIMARY KEY (box_id, check_id)
);

CREATE TABLE IF NOT EXISTS scores (
    box_id TEXT PRIMARY KEY,
    scenario_name TEXT NOT NULL,
    total INTEGER NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS adversary_log (
    box_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    action TEXT NOT NULL,
    issued_at REAL NOT NULL,
    params_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scenarios (
    scenario_name TEXT PRIMARY KEY,
    rubric_json TEXT NOT NULL,
    adversary_json TEXT NOT NULL,
    uploaded_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS engine_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class Store:
    def __init__(self, db_path: str):
        """Open (creating if absent) the sqlite3 file at db_path and ensure
        the schema exists."""
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    # --- enrollment.py -----------------------------------------------------

    def get_token(self, token: str) -> Optional[dict]:
        """Returns {"scenario_name": str, "expires_at": float,
        "consumed_at": float | None} or None if the token is unknown."""
        cur = self._conn.execute(
            "SELECT scenario_name, expires_at, consumed_at FROM enrollment_tokens "
            "WHERE token = ?",
            (token,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return {
            "scenario_name": row["scenario_name"],
            "expires_at": row["expires_at"],
            "consumed_at": row["consumed_at"],
        }

    def consume_token(self, token: str) -> None:
        import time

        with self._lock:
            self._conn.execute(
                "UPDATE enrollment_tokens SET consumed_at = ? WHERE token = ?",
                (time.time(), token),
            )
            self._conn.commit()

    def create_box(self, box_id: str, public_key: str, scenario_name: str) -> None:
        import time

        now = time.time()
        with self._lock:
            self._conn.execute(
                "INSERT INTO boxes (box_id, public_key, scenario_name, enrolled_at, "
                "last_seq, last_boot_id, t0) VALUES (?, ?, ?, ?, 0, NULL, NULL)",
                (box_id, public_key, scenario_name, now),
            )
            self._conn.commit()

    def create_token(self, token: str, scenario_name: str, expires_at: float) -> None:
        """Insert a fresh, unconsumed enrollment token. Used by the
        POST /admin/tokens endpoint (engine/server.py)."""
        with self._lock:
            self._conn.execute(
                "INSERT INTO enrollment_tokens (token, scenario_name, expires_at, "
                "consumed_at) VALUES (?, ?, ?, NULL)",
                (token, scenario_name, expires_at),
            )
            self._conn.commit()

    # --- checkin.py ----------------------------------------------------------

    def get_box(self, box_id: str) -> Optional[BoxRecord]:
        cur = self._conn.execute(
            "SELECT box_id, public_key, scenario_name, enrolled_at, last_seq, "
            "last_boot_id, t0 FROM boxes WHERE box_id = ?",
            (box_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return BoxRecord(
            box_id=row["box_id"],
            public_key=row["public_key"],
            scenario_name=row["scenario_name"],
            enrolled_at=row["enrolled_at"],
            last_seq=row["last_seq"],
            last_boot_id=row["last_boot_id"],
            t0=row["t0"],
        )

    def set_t0_if_unset(self, box_id: str, t0: float) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE boxes SET t0 = ? WHERE box_id = ? AND t0 IS NULL",
                (t0, box_id),
            )
            self._conn.commit()

    def update_box_seq(self, box_id: str, seq: int, boot_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE boxes SET last_seq = ?, last_boot_id = ? WHERE box_id = ?",
                (seq, boot_id, box_id),
            )
            self._conn.commit()

    def save_checkin(self, box_id: str, seq: int, received_at: float,
                      bundle_json: str) -> None:
        """Audit log insert into `checkins`."""
        with self._lock:
            self._conn.execute(
                "INSERT INTO checkins (box_id, seq, received_at, bundle_json) "
                "VALUES (?, ?, ?, ?)",
                (box_id, seq, received_at, bundle_json),
            )
            self._conn.commit()

    def upsert_score(self, box_id: str, scenario_name: str, total: int) -> None:
        import time

        now = time.time()
        with self._lock:
            self._conn.execute(
                "INSERT INTO scores (box_id, scenario_name, total, updated_at) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(box_id) DO UPDATE SET "
                "scenario_name = excluded.scenario_name, "
                "total = excluded.total, "
                "updated_at = excluded.updated_at",
                (box_id, scenario_name, total, now),
            )
            self._conn.commit()

    # --- sla.py --------------------------------------------------------------

    def get_sla_state(self, box_id: str, check_id: str) -> Optional[SlaStateRecord]:
        cur = self._conn.execute(
            "SELECT box_id, check_id, state, consec_ok, consec_fail, "
            "last_credited_at, accrued_points FROM sla_state "
            "WHERE box_id = ? AND check_id = ?",
            (box_id, check_id),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return SlaStateRecord(
            box_id=row["box_id"],
            check_id=row["check_id"],
            state=row["state"],
            consec_ok=row["consec_ok"],
            consec_fail=row["consec_fail"],
            last_credited_at=row["last_credited_at"],
            accrued_points=row["accrued_points"],
        )

    def save_sla_state(self, rec: SlaStateRecord) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO sla_state (box_id, check_id, state, consec_ok, "
                "consec_fail, last_credited_at, accrued_points) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(box_id, check_id) DO UPDATE SET "
                "state = excluded.state, "
                "consec_ok = excluded.consec_ok, "
                "consec_fail = excluded.consec_fail, "
                "last_credited_at = excluded.last_credited_at, "
                "accrued_points = excluded.accrued_points",
                (
                    rec.box_id,
                    rec.check_id,
                    rec.state,
                    rec.consec_ok,
                    rec.consec_fail,
                    rec.last_credited_at,
                    rec.accrued_points,
                ),
            )
            self._conn.commit()

    # --- adversary_oracle.py ---------------------------------------------------

    def get_issued_event_ids(self, box_id: str) -> set:
        cur = self._conn.execute(
            "SELECT event_id FROM adversary_log WHERE box_id = ?", (box_id,)
        )
        return {row["event_id"] for row in cur.fetchall()}

    def log_adversary_event(self, box_id: str, event_id: str, action: str,
                             issued_at: float, params: dict) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO adversary_log (box_id, event_id, action, issued_at, "
                "params_json) VALUES (?, ?, ?, ?, ?)",
                (box_id, event_id, action, issued_at, json.dumps(params)),
            )
            self._conn.commit()

    # --- leaderboard.py --------------------------------------------------------

    def get_scores(self, scenario_name: str) -> list:
        """Returns list[ScoreRow], ranked descending by total."""
        cur = self._conn.execute(
            "SELECT box_id, scenario_name, total, updated_at FROM scores "
            "WHERE scenario_name = ? ORDER BY total DESC",
            (scenario_name,),
        )
        return [
            ScoreRow(
                box_id=row["box_id"],
                scenario_name=row["scenario_name"],
                total=row["total"],
                updated_at=row["updated_at"],
            )
            for row in cur.fetchall()
        ]

    # --- engine/server.py: multi-scenario support (POST /admin/scenarios) ---

    def save_scenario(self, scenario_name: str, rubric_json: str,
                       adversary_json: str) -> None:
        """Insert or replace the rubric+adversary record for a scenario."""
        import time

        with self._lock:
            self._conn.execute(
                "INSERT INTO scenarios (scenario_name, rubric_json, adversary_json, "
                "uploaded_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(scenario_name) DO UPDATE SET "
                "rubric_json = excluded.rubric_json, "
                "adversary_json = excluded.adversary_json, "
                "uploaded_at = excluded.uploaded_at",
                (scenario_name, rubric_json, adversary_json, time.time()),
            )
            self._conn.commit()

    def get_scenario(self, scenario_name: str) -> Optional[dict]:
        """Returns {"rubric_json": str, "adversary_json": str,
        "uploaded_at": float} or None if the scenario is unknown."""
        cur = self._conn.execute(
            "SELECT rubric_json, adversary_json, uploaded_at FROM scenarios "
            "WHERE scenario_name = ?",
            (scenario_name,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        return {
            "rubric_json": row["rubric_json"],
            "adversary_json": row["adversary_json"],
            "uploaded_at": row["uploaded_at"],
        }

    # --- engine/server.py: persisted server_secret (§4) ---------------------

    def get_meta(self, key: str) -> Optional[str]:
        cur = self._conn.execute(
            "SELECT value FROM engine_meta WHERE key = ?", (key,)
        )
        row = cur.fetchone()
        return row["value"] if row is not None else None

    def set_meta(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO engine_meta (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
            self._conn.commit()
