"""SQLite-backed storage. See architecture.md §11.2."""
import contextlib
import json
import os
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

from common.schema import SLA_HISTORY_MAX
from engine.store_schema import SCHEMA as _SCHEMA


def _load_sla_history(raw) -> list:
    """Decode a history_json value into a capped oldest->newest state list."""
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return []
    if not isinstance(data, list):
        return []
    out = [str(item).upper() for item in data if str(item).upper() in ("UP", "DOWN")]
    return out[-SLA_HISTORY_MAX:]


def _dump_sla_history(history) -> str:
    values = [str(item).upper() for item in (history or [])
              if str(item).upper() in ("UP", "DOWN")]
    return json.dumps(values[-SLA_HISTORY_MAX:])



@dataclass
class BoxRecord:
    box_id: str
    public_key: str
    scenario_name: str
    scenario_version: int
    enrolled_at: float
    last_seq: int
    last_boot_id: Optional[str]
    t0: Optional[float]
    competition_id: Optional[str] = None
    player_id: Optional[str] = None


@dataclass
class SlaStateRecord:
    box_id: str
    check_id: str
    state: str  # "UP" | "DOWN"
    consec_ok: int
    consec_fail: int
    last_credited_at: float
    accrued_points: int
    last_observed_at: float = 0.0
    last_changed_at: float = 0.0
    history: list = field(default_factory=list)  # list[str], oldest -> newest


@dataclass
class ScoreRow:
    box_id: str
    scenario_name: str
    total: int
    updated_at: float
    first_scored_at: float = 0.0
    hardening_points: int = 0
    service_points: int = 0


@dataclass
class CompetitionRecord:
    id: str
    slug: str
    name: str
    scenario_name: str
    scenario_version: int
    status: str
    join_open: bool
    max_players: int
    duration_s: int
    workshop_pool_code: Optional[str]
    theme_json: Optional[str]
    join_instructions: Optional[str]
    created_at: float
    started_at: Optional[float]
    ended_at: Optional[float]


@dataclass
class PlayerRecord:
    player_id: str
    competition_id: str
    display_name: str
    display_name_norm: str
    status: str
    join_code_hash: Optional[str]
    join_code_plain: Optional[str]
    join_code_expires_at: Optional[float]
    joined_at: float
    started_at: Optional[float]
    ends_at: Optional[float]
    finished_at: Optional[float]
    box_id: Optional[str]
    claim_url: Optional[str]
    claim_uid: Optional[str]
    claim_ticket: Optional[str]
    claim_expires_at: Optional[float]
    claim_error: Optional[str] = None
    claim_attempts: int = 0
    claim_last_attempt_at: Optional[float] = None
    claim_last_poll_at: Optional[float] = None


@dataclass
class AuditRecord:
    id: int
    ts: float
    actor: str
    action: str
    competition_id: Optional[str]
    player_id: Optional[str]
    details_json: Optional[str]
    remote_addr: Optional[str]


@dataclass
class AdminSessionRecord:
    session_hash: str
    username: str
    csrf_token: str
    created_at: float
    expires_at: float




class Store:
    def __init__(self, db_path: str):
        """Open (creating if absent) the sqlite3 file at db_path and ensure
        the schema exists.

        The engine DB holds the engine-only rubric, the adversary server
        secret, live enrollment tokens and signed check-ins. SQLite creates a
        new file with 0666 & ~umask (usually 0644), which is world-readable on
        a multi-user engine host; create/tighten it to 0600.
        """
        # Reentrant so Store methods can run inside atomic() on the same thread.
        self._lock = threading.RLock()
        self._txn_depth = 0
        if db_path != ":memory:":
            directory = os.path.dirname(os.path.abspath(db_path))
            if directory and not os.path.isdir(directory):
                os.makedirs(directory, mode=0o700, exist_ok=True)
            fd = os.open(db_path, os.O_RDWR | os.O_CREAT, 0o600)
            os.close(fd)
            try:
                os.chmod(db_path, 0o600)
            except OSError:
                pass
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(_SCHEMA)
            self._migrate_schema()
            self._conn.commit()

    def _table_columns(self, table: str) -> dict:
        rows = self._conn.execute(f"PRAGMA table_info({table})").fetchall()
        return {row["name"]: row for row in rows}

    def _migrate_schema(self) -> None:
        """Bring a pre-1.0 database up to the current shape in place.

        - scenarios: single row per name -> (name, version) composite key
        - scores: add immutable first_scored_at for stable tie-breaks
        - adversary_log: persist fire_time/affects_check/restored_at so the
          engine can enforce the outage floor
        """
        tables = {
            row["name"] for row in self._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        scenario_cols = self._table_columns("scenarios")
        if "scenarios" in tables:
            pk_cols = [name for name, row in scenario_cols.items() if row["pk"]]
            if "scenario_version" not in scenario_cols or pk_cols != [
                    "scenario_name", "scenario_version"]:
                rows = self._conn.execute(
                    "SELECT scenario_name, rubric_json, adversary_json, uploaded_at "
                    "FROM scenarios"
                ).fetchall() if scenario_cols else []
                self._conn.execute("DROP TABLE IF EXISTS scenarios__new")
                self._conn.execute(
                    "CREATE TABLE scenarios__new ("
                    "scenario_name TEXT NOT NULL, scenario_version INTEGER NOT NULL, "
                    "rubric_json TEXT NOT NULL, adversary_json TEXT NOT NULL, "
                    "uploaded_at REAL NOT NULL, "
                    "PRIMARY KEY (scenario_name, scenario_version))"
                )
                for row in rows:
                    try:
                        rubric = json.loads(row["rubric_json"])
                        version = rubric.get("scenario_version", 0)
                        if isinstance(version, bool) or not isinstance(version, int) or version < 0:
                            version = 0
                    except (ValueError, TypeError, AttributeError):
                        version = 0
                    self._conn.execute(
                        "INSERT OR REPLACE INTO scenarios__new "
                        "(scenario_name, scenario_version, rubric_json, "
                        "adversary_json, uploaded_at) VALUES (?, ?, ?, ?, ?)",
                        (row["scenario_name"], version, row["rubric_json"],
                         row["adversary_json"], row["uploaded_at"]),
                    )
                self._conn.execute("DROP TABLE scenarios")
                self._conn.execute("ALTER TABLE scenarios__new RENAME TO scenarios")

        score_cols = self._table_columns("scores")
        if score_cols and "first_scored_at" not in score_cols:
            self._conn.execute(
                "ALTER TABLE scores ADD COLUMN first_scored_at REAL NOT NULL DEFAULT 0"
            )
            self._conn.execute(
                "UPDATE scores SET first_scored_at = updated_at WHERE first_scored_at = 0"
            )

        adv_cols = self._table_columns("adversary_log")
        if adv_cols:
            for column, decl in (
                ("fire_time", "REAL"),
                ("affects_check", "TEXT"),
                ("restored_at", "REAL"),
            ):
                if column not in adv_cols:
                    self._conn.execute(
                        f"ALTER TABLE adversary_log ADD COLUMN {column} {decl}"
                    )

        # --- ranked competition mode (v1.1) -------------------------------
        for table, columns in (
            ("boxes", (("competition_id", "TEXT"), ("player_id", "TEXT"))),
            ("scores", (
                ("hardening_points", "INTEGER NOT NULL DEFAULT 0"),
                ("service_points", "INTEGER NOT NULL DEFAULT 0"),
                ("score_json", "TEXT"),
            )),
            ("scenarios", (
                ("services_json", "TEXT NOT NULL DEFAULT '[]'"),
                ("pool_json", "TEXT"),
            )),
            ("sla_state", (
                ("last_observed_at", "REAL NOT NULL DEFAULT 0"),
                ("last_changed_at", "REAL NOT NULL DEFAULT 0"),
                ("history_json", "TEXT NOT NULL DEFAULT '[]'"),
            )),
            ("enrollment_tokens", (
                ("competition_id", "TEXT"), ("player_id", "TEXT"),
            )),
            ("players", (
                ("join_code_plain", "TEXT"),
                ("claim_error", "TEXT"),
                ("claim_attempts", "INTEGER NOT NULL DEFAULT 0"),
                ("claim_last_attempt_at", "REAL"),
                ("claim_last_poll_at", "REAL"),
            )),
        ):
            cols = self._table_columns(table)
            if not cols:
                continue
            for column, decl in columns:
                if column not in cols:
                    self._conn.execute(
                        f"ALTER TABLE {table} ADD COLUMN {column} {decl}"
                    )

    def _commit(self) -> None:
        """Commit unless an enclosing atomic() block owns the transaction."""
        if self._txn_depth == 0:
            self._conn.commit()

    @contextlib.contextmanager
    def atomic(self):
        """Run several Store calls as one transaction: all commit together on
        success, all roll back on any exception. Holds the store lock for the
        duration, so other threads' Store calls wait."""
        with self._lock:
            self._txn_depth += 1
            try:
                yield
                if self._txn_depth == 1:
                    self._conn.commit()
            except BaseException:
                if self._txn_depth == 1:
                    self._conn.rollback()
                raise
            finally:
                self._txn_depth -= 1

    # --- enrollment.py -----------------------------------------------------

    def get_token(self, token: str) -> Optional[dict]:
        """Returns {"scenario_name": str, "expires_at": float,
        "consumed_at": float | None} or None if the token is unknown."""
        with self._lock:
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
            self._commit()

    def create_box(self, box_id: str, public_key: str, scenario_name: str,
                    scenario_version: int = 0, competition_id: Optional[str] = None,
                    player_id: Optional[str] = None,
                    t0: Optional[float] = None) -> None:
        import time

        now = time.time()
        with self._lock:
            self._conn.execute(
                "INSERT INTO boxes (box_id, public_key, scenario_name, scenario_version, "
                "enrolled_at, last_seq, last_boot_id, t0, competition_id, player_id) "
                "VALUES (?, ?, ?, ?, ?, 0, NULL, ?, ?, ?)",
                (box_id, public_key, scenario_name, scenario_version, now, t0,
                 competition_id, player_id),
            )
            self._commit()

    def enroll_box_atomic(self, token: str, box_id: str, public_key: str,
                            scenario_name: str, scenario_version: int = 0) -> str:
        """Atomically validate and consume token and create box.

        Returns one of: ok | unknown_token | already_consumed | expired |
        scenario_mismatch | duplicate_box.
        """
        import time

        now = time.time()
        with self._lock:
            row = self._conn.execute(
                "SELECT scenario_name, expires_at, consumed_at "
                "FROM enrollment_tokens WHERE token = ?",
                (token,),
            ).fetchone()
            if row is None:
                return "unknown_token"
            if row["consumed_at"] is not None:
                return "already_consumed"
            if row["expires_at"] < now:
                return "expired"
            if row["scenario_name"] != scenario_name:
                return "scenario_mismatch"
            try:
                self._conn.execute(
                    "INSERT INTO boxes (box_id, public_key, scenario_name, "
                    "scenario_version, enrolled_at, last_seq, last_boot_id, t0) "
                    "VALUES (?, ?, ?, ?, ?, 0, NULL, NULL)",
                    (box_id, public_key, row["scenario_name"], scenario_version, now),
                )
            except sqlite3.IntegrityError:
                self._conn.rollback()
                return "duplicate_box"
            self._conn.execute(
                "UPDATE enrollment_tokens SET consumed_at = ? WHERE token = ?",
                (now, token),
            )
            self._commit()
            return "ok"

    def create_token(self, token: str, scenario_name: str, expires_at: float) -> None:
        """Insert a fresh, unconsumed enrollment token."""
        with self._lock:
            self._conn.execute(
                "INSERT INTO enrollment_tokens (token, scenario_name, expires_at, "
                "consumed_at) VALUES (?, ?, ?, NULL)",
                (token, scenario_name, expires_at),
            )
            self._commit()

    # --- checkin.py ----------------------------------------------------------

    def get_box(self, box_id: str) -> Optional[BoxRecord]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT box_id, public_key, scenario_name, scenario_version, enrolled_at, "
                "last_seq, last_boot_id, t0, competition_id, player_id "
                "FROM boxes WHERE box_id = ?",
                (box_id,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return BoxRecord(
            box_id=row["box_id"],
            public_key=row["public_key"],
            scenario_name=row["scenario_name"],
            scenario_version=row["scenario_version"],
            enrolled_at=row["enrolled_at"],
            last_seq=row["last_seq"],
            last_boot_id=row["last_boot_id"],
            t0=row["t0"],
            competition_id=row["competition_id"],
            player_id=row["player_id"],
        )

    def set_t0_if_unset(self, box_id: str, t0: float) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE boxes SET t0 = ? WHERE box_id = ? AND t0 IS NULL",
                (t0, box_id),
            )
            self._commit()

    def get_or_set_t0(self, box_id: str, now: float) -> float:
        """Atomically set T0 if unset and return the authoritative value.

        Reading `box.t0` before the transaction meant two concurrent first
        check-ins could compute different T0s; the scheduler for the loser used
        its own receipt time instead of the committed anchor.
        """
        with self._lock:
            self._conn.execute(
                "UPDATE boxes SET t0 = ? WHERE box_id = ? AND t0 IS NULL",
                (now, box_id),
            )
            row = self._conn.execute(
                "SELECT t0 FROM boxes WHERE box_id = ?", (box_id,)
            ).fetchone()
            self._commit()
            return float(row["t0"]) if row is not None and row["t0"] is not None else now

    def update_box_seq(self, box_id: str, seq: int, boot_id: str) -> bool:
        """Advance last_seq only if seq is strictly greater. Atomic via guard."""
        with self._lock:
            cur = self._conn.execute(
                "UPDATE boxes SET last_seq = ?, last_boot_id = ? "
                "WHERE box_id = ? AND last_seq < ?",
                (seq, boot_id, box_id, seq),
            )
            self._commit()
            return cur.rowcount == 1

    def save_checkin(self, box_id: str, seq: int, received_at: float,
                      bundle_json: str) -> None:
        """Audit log insert into `checkins`."""
        with self._lock:
            self._conn.execute(
                "INSERT INTO checkins (box_id, seq, received_at, bundle_json) "
                "VALUES (?, ?, ?, ?)",
                (box_id, seq, received_at, bundle_json),
            )
            self._commit()

    def upsert_score(self, box_id: str, scenario_name: str, total: int,
                     hardening_points: Optional[int] = None,
                     service_points: int = 0,
                     score_json: Optional[str] = None) -> None:
        import time

        now = time.time()
        hardening = total if hardening_points is None else hardening_points
        with self._lock:
            self._conn.execute(
                "INSERT INTO scores (box_id, scenario_name, total, updated_at, "
                "first_scored_at, hardening_points, service_points, score_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(box_id) DO UPDATE SET "
                "scenario_name = excluded.scenario_name, "
                "total = excluded.total, "
                "updated_at = excluded.updated_at, "
                "hardening_points = excluded.hardening_points, "
                "service_points = excluded.service_points, "
                "score_json = excluded.score_json",
                (box_id, scenario_name, total, now, now, hardening,
                 service_points, score_json),
            )
            self._commit()

    def get_score(self, box_id: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT box_id, scenario_name, total, updated_at, first_scored_at, "
                "hardening_points, service_points, score_json "
                "FROM scores WHERE box_id = ?", (box_id,)
            ).fetchone()
        if row is None:
            return None
        return {
            "box_id": row["box_id"], "scenario_name": row["scenario_name"],
            "total": row["total"], "updated_at": row["updated_at"],
            "first_scored_at": row["first_scored_at"],
            "hardening_points": row["hardening_points"],
            "service_points": row["service_points"],
            "score_json": row["score_json"],
        }

    # --- sla.py --------------------------------------------------------------

    def get_sla_state(self, box_id: str, check_id: str) -> Optional[SlaStateRecord]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT box_id, check_id, state, consec_ok, consec_fail, "
                "last_credited_at, accrued_points, last_observed_at, "
                "last_changed_at, history_json "
                "FROM sla_state WHERE box_id = ? AND check_id = ?",
                (box_id, check_id),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return SlaStateRecord(
            box_id=row["box_id"], check_id=row["check_id"], state=row["state"],
            consec_ok=row["consec_ok"], consec_fail=row["consec_fail"],
            last_credited_at=row["last_credited_at"],
            accrued_points=row["accrued_points"],
            last_observed_at=row["last_observed_at"],
            last_changed_at=row["last_changed_at"],
            history=_load_sla_history(row["history_json"]),
        )

    def save_sla_state(self, rec: SlaStateRecord) -> None:
        rec.history = _load_sla_history(_dump_sla_history(rec.history))
        with self._lock:
            self._conn.execute(
                "INSERT INTO sla_state (box_id, check_id, state, consec_ok, "
                "consec_fail, last_credited_at, accrued_points, last_observed_at, "
                "last_changed_at, history_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(box_id, check_id) DO UPDATE SET "
                "state = excluded.state, consec_ok = excluded.consec_ok, "
                "consec_fail = excluded.consec_fail, "
                "last_credited_at = excluded.last_credited_at, "
                "accrued_points = excluded.accrued_points, "
                "last_observed_at = excluded.last_observed_at, "
                "last_changed_at = excluded.last_changed_at, "
                "history_json = excluded.history_json",
                (rec.box_id, rec.check_id, rec.state, rec.consec_ok,
                 rec.consec_fail, rec.last_credited_at, rec.accrued_points,
                 rec.last_observed_at, rec.last_changed_at,
                 _dump_sla_history(rec.history)),
            )
            self._commit()

    def update_sla_atomic(self, box_id: str, check_id: str, apply_fn,
                           observed_at: Optional[float] = None) -> "SlaStateRecord":
        """Atomically read-modify-write an SLA state row via ``apply_fn``."""
        observed = time.time() if observed_at is None else observed_at
        with self._lock:
            cur = self._conn.execute(
                "SELECT box_id, check_id, state, consec_ok, consec_fail, "
                "last_credited_at, accrued_points, last_observed_at, "
                "last_changed_at, history_json "
                "FROM sla_state WHERE box_id = ? AND check_id = ?",
                (box_id, check_id),
            )
            row = cur.fetchone()
            old_state = None if row is None else row["state"]
            rec = None if row is None else SlaStateRecord(
                box_id=row["box_id"], check_id=row["check_id"], state=row["state"],
                consec_ok=row["consec_ok"], consec_fail=row["consec_fail"],
                last_credited_at=row["last_credited_at"],
                accrued_points=row["accrued_points"],
                last_observed_at=row["last_observed_at"],
                last_changed_at=row["last_changed_at"],
                history=_load_sla_history(row["history_json"]),
            )
            new_rec = apply_fn(rec)
            new_rec.last_observed_at = observed
            if old_state is None or old_state != new_rec.state:
                new_rec.last_changed_at = observed
            elif not new_rec.last_changed_at:
                new_rec.last_changed_at = observed
            # One tick per update: record the post-hysteresis state this
            # check-in settled on, keeping a bounded oldest->newest ring.
            history = list(new_rec.history or [])
            history.append(new_rec.state)
            new_rec.history = history[-SLA_HISTORY_MAX:]
            self._conn.execute(
                "INSERT INTO sla_state (box_id, check_id, state, consec_ok, "
                "consec_fail, last_credited_at, accrued_points, last_observed_at, "
                "last_changed_at, history_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(box_id, check_id) DO UPDATE SET "
                "state = excluded.state, consec_ok = excluded.consec_ok, "
                "consec_fail = excluded.consec_fail, "
                "last_credited_at = excluded.last_credited_at, "
                "accrued_points = excluded.accrued_points, "
                "last_observed_at = excluded.last_observed_at, "
                "last_changed_at = excluded.last_changed_at, "
                "history_json = excluded.history_json",
                (new_rec.box_id, new_rec.check_id, new_rec.state, new_rec.consec_ok,
                 new_rec.consec_fail, new_rec.last_credited_at,
                 new_rec.accrued_points, new_rec.last_observed_at,
                 new_rec.last_changed_at, _dump_sla_history(new_rec.history)),
            )
            self._commit()
            return new_rec

    # --- adversary_oracle.py ---------------------------------------------------

    def get_issued_event_ids(self, box_id: str) -> set:
        with self._lock:
            cur = self._conn.execute(
                "SELECT event_id FROM adversary_log WHERE box_id = ?", (box_id,)
            )
            return {row["event_id"] for row in cur.fetchall()}

    def get_issued_directives(self, box_id: str) -> list:
        """Every directive issued to box_id, oldest first, as
        [{"event_id", "action", "params", "fire_time", "affects_check"}]."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT event_id, action, params_json, fire_time, affects_check "
                "FROM adversary_log WHERE box_id = ? ORDER BY issued_at, rowid",
                (box_id,),
            )
            rows = cur.fetchall()
        return [
            {"event_id": r["event_id"], "action": r["action"],
             "params": json.loads(r["params_json"]),
             "fire_time": r["fire_time"], "affects_check": r["affects_check"]}
            for r in rows
        ]

    def log_adversary_event(self, box_id: str, event_id: str, action: str,
                             issued_at: float, params: dict,
                             fire_time: Optional[float] = None,
                             affects_check: Optional[str] = None) -> bool:
        """Record directive fire; True if this call won the race."""
        with self._lock:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO adversary_log (box_id, event_id, action, "
                "issued_at, params_json, fire_time, affects_check) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (box_id, event_id, action, issued_at, json.dumps(params),
                 fire_time, affects_check),
            )
            self._commit()
            return cur.rowcount == 1

    def get_active_adversary_effects(self, box_id: str,
                                     received_at: float) -> list:
        """Issued events that name an SLA check and are not restored yet."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT event_id, action, params_json, fire_time, affects_check, "
                "issued_at FROM adversary_log "
                "WHERE box_id = ? AND affects_check IS NOT NULL "
                "AND restored_at IS NULL AND fire_time IS NOT NULL "
                "AND fire_time <= ? ORDER BY issued_at, rowid",
                (box_id, received_at),
            )
            rows = cur.fetchall()
        return [
            {"event_id": r["event_id"], "action": r["action"],
             "params": json.loads(r["params_json"]),
             "fire_time": r["fire_time"], "affects_check": r["affects_check"],
             "issued_at": r["issued_at"]}
            for r in rows
        ]

    def mark_adversary_restored(self, box_id: str, event_id: str,
                                restored_at: float) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE adversary_log SET restored_at = ? "
                "WHERE box_id = ? AND event_id = ? AND restored_at IS NULL",
                (restored_at, box_id, event_id),
            )
            self._commit()

    # --- leaderboard.py --------------------------------------------------------

    def get_scores(self, scenario_name: str) -> list:
        """Return scores ranked by total, then immutable first-scored time.

        Ties used to be ordered by the *last* check-in timestamp ascending,
        which ranked the box that had been silent longest above active peers
        and let a player freeze a winning tie by stopping check-ins.
        """
        with self._lock:
            cur = self._conn.execute(
                "SELECT box_id, scenario_name, total, updated_at, first_scored_at "
                "FROM scores WHERE scenario_name = ? "
                "ORDER BY total DESC, first_scored_at ASC, box_id ASC",
                (scenario_name,),
            )
            rows = cur.fetchall()
        return [
            ScoreRow(
                box_id=row["box_id"],
                scenario_name=row["scenario_name"],
                total=row["total"],
                updated_at=row["updated_at"],
                first_scored_at=row["first_scored_at"],
            )
            for row in rows
        ]

    # --- engine/server.py: multi-scenario support (POST /admin/scenarios) ---

    def save_scenario(self, scenario_name: str, scenario_version: int,
                       rubric_json: str, adversary_json: str,
                       services_json: str = "[]",
                       pool_json: Optional[str] = None) -> None:
        """Insert or replace one (name, version) scenario record."""
        with self._lock:
            self._conn.execute(
                "INSERT INTO scenarios (scenario_name, scenario_version, rubric_json, "
                "adversary_json, uploaded_at, services_json, pool_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(scenario_name, scenario_version) DO UPDATE SET "
                "rubric_json = excluded.rubric_json, "
                "adversary_json = excluded.adversary_json, "
                "uploaded_at = excluded.uploaded_at, "
                "services_json = excluded.services_json, "
                "pool_json = excluded.pool_json",
                (scenario_name, scenario_version, rubric_json, adversary_json,
                 time.time(), services_json, pool_json),
            )
            self._commit()

    def get_scenario(self, scenario_name: str,
                     scenario_version: int) -> Optional[dict]:
        """Return the record for an exact (name, version), or None."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT rubric_json, adversary_json, uploaded_at, services_json, "
                "pool_json FROM scenarios WHERE scenario_name = ? AND scenario_version = ?",
                (scenario_name, scenario_version),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return {
            "rubric_json": row["rubric_json"],
            "adversary_json": row["adversary_json"],
            "uploaded_at": row["uploaded_at"],
            "services_json": row["services_json"],
            "pool_json": row["pool_json"],
        }

    def list_scenarios(self) -> list:
        with self._lock:
            rows = self._conn.execute(
                "SELECT scenario_name, scenario_version, uploaded_at FROM scenarios "
                "ORDER BY uploaded_at DESC"
            ).fetchall()
        return [(r["scenario_name"], r["scenario_version"], r["uploaded_at"])
                for r in rows]

    def get_latest_scenario_version(self, scenario_name: str) -> Optional[int]:
        with self._lock:
            row = self._conn.execute(
                "SELECT MAX(scenario_version) AS version FROM scenarios "
                "WHERE scenario_name = ?",
                (scenario_name,),
            ).fetchone()
        return row["version"] if row is not None else None

    # --- ranked competition mode -------------------------------------------

    @staticmethod
    def _competition_from_row(row) -> CompetitionRecord:
        return CompetitionRecord(
            id=row["id"], slug=row["slug"], name=row["name"],
            scenario_name=row["scenario_name"],
            scenario_version=row["scenario_version"],
            status=row["status"], join_open=bool(row["join_open"]),
            max_players=row["max_players"], duration_s=row["duration_s"],
            workshop_pool_code=row["workshop_pool_code"],
            theme_json=row["theme_json"],
            join_instructions=row["join_instructions"],
            created_at=row["created_at"], started_at=row["started_at"],
            ended_at=row["ended_at"],
        )

    @staticmethod
    def _player_from_row(row) -> PlayerRecord:
        return PlayerRecord(
            player_id=row["player_id"], competition_id=row["competition_id"],
            display_name=row["display_name"],
            display_name_norm=row["display_name_norm"], status=row["status"],
            join_code_hash=row["join_code_hash"],
            join_code_plain=row["join_code_plain"],
            join_code_expires_at=row["join_code_expires_at"],
            joined_at=row["joined_at"], started_at=row["started_at"],
            ends_at=row["ends_at"], finished_at=row["finished_at"],
            box_id=row["box_id"], claim_url=row["claim_url"],
            claim_uid=row["claim_uid"], claim_ticket=row["claim_ticket"],
            claim_expires_at=row["claim_expires_at"],
            claim_error=row["claim_error"],
            claim_attempts=row["claim_attempts"] or 0,
            claim_last_attempt_at=row["claim_last_attempt_at"],
            claim_last_poll_at=row["claim_last_poll_at"],
        )

    def create_competition(self, slug: str, name: str, scenario_name: str,
                           scenario_version: int, max_players: int,
                           duration_s: int, workshop_pool_code: Optional[str] = None,
                           theme_json: Optional[str] = None,
                           join_instructions: Optional[str] = None,
                           status: str = "draft", join_open: bool = False) -> CompetitionRecord:
        comp_id = uuid.uuid4().hex
        now = time.time()
        with self._lock:
            self._conn.execute(
                "INSERT INTO competitions (id, slug, name, scenario_name, "
                "scenario_version, status, join_open, max_players, duration_s, "
                "workshop_pool_code, theme_json, join_instructions, created_at, "
                "started_at, ended_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
                (comp_id, slug, name, scenario_name, scenario_version, status,
                 1 if join_open else 0, max_players, duration_s, workshop_pool_code,
                 theme_json, join_instructions, now),
            )
            self._commit()
        return self.get_competition(comp_id)

    def get_competition(self, comp_id: str) -> Optional[CompetitionRecord]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM competitions WHERE id = ?", (comp_id,)
            ).fetchone()
        return None if row is None else self._competition_from_row(row)

    def get_competition_by_slug(self, slug: str) -> Optional[CompetitionRecord]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM competitions WHERE slug = ?", (slug,)
            ).fetchone()
        return None if row is None else self._competition_from_row(row)

    def list_competitions(self) -> list:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM competitions ORDER BY created_at DESC"
            ).fetchall()
        return [self._competition_from_row(r) for r in rows]

    def update_competition(self, comp_id: str, **fields) -> None:
        allowed = {"slug", "name", "scenario_name", "scenario_version", "status",
                   "join_open", "max_players", "duration_s", "workshop_pool_code",
                   "theme_json", "join_instructions", "started_at", "ended_at"}
        sets, vals = [], []
        for k, v in fields.items():
            if k not in allowed:
                continue
            sets.append(f"{k} = ?")
            vals.append(int(v) if k == "join_open" and isinstance(v, bool) else v)
        if not sets:
            return
        vals.append(comp_id)
        with self._lock:
            self._conn.execute(
                f"UPDATE competitions SET {', '.join(sets)} WHERE id = ?", vals
            )
            self._commit()

    def start_competition(self, comp_id: str) -> bool:
        now = time.time()
        with self._lock:
            cur = self._conn.execute(
                "UPDATE competitions SET status = 'live', join_open = 1, "
                "started_at = COALESCE(started_at, ?) WHERE id = ? AND status = 'draft'",
                (now, comp_id),
            )
            self._commit()
            return cur.rowcount == 1

    def end_competition(self, comp_id: str) -> bool:
        now = time.time()
        with self._lock:
            cur = self._conn.execute(
                "UPDATE competitions SET status = 'ended', join_open = 0, "
                "ended_at = ? WHERE id = ? AND status = 'live'", (now, comp_id)
            )
            self._conn.execute(
                "UPDATE players SET status = 'finished', finished_at = ?, "
                "ends_at = MIN(COALESCE(ends_at, ?), ?) "
                "WHERE competition_id = ? AND status = 'running'",
                (now, now, now, comp_id),
            )
            self._commit()
            return cur.rowcount == 1

    def set_join_open(self, comp_id: str, open_: bool) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE competitions SET join_open = ? WHERE id = ?",
                (1 if open_ else 0, comp_id),
            )
            self._commit()

    def delete_competition(self, comp_id: str) -> bool:
        """Remove an **ended** competition and its player slots.

        Boxes and their scores survive: they are already historical once the
        run ends, and deleting them would erase that scenario's leaderboard.
        Player/player_boxes rows go because their competition no longer exists.
        Returns False if the competition is unknown or still draft/live --
        callers end it first (releasing its VMs) rather than deleting a run out
        from under its players.
        """
        with self.atomic():
            row = self._conn.execute(
                "SELECT status FROM competitions WHERE id = ?", (comp_id,)
            ).fetchone()
            if row is None or row["status"] != "ended":
                return False
            self._conn.execute(
                "DELETE FROM player_boxes WHERE player_id IN "
                "(SELECT player_id FROM players WHERE competition_id = ?)",
                (comp_id,),
            )
            self._conn.execute(
                "DELETE FROM players WHERE competition_id = ?", (comp_id,)
            )
            self._conn.execute(
                "DELETE FROM competitions WHERE id = ?", (comp_id,)
            )
        return True

    def count_players(self, comp_id: str, include_removed: bool = False) -> int:
        with self._lock:
            if include_removed:
                row = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM players WHERE competition_id = ?",
                    (comp_id,),
                ).fetchone()
            else:
                row = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM players WHERE competition_id = ? "
                    "AND status != 'removed'", (comp_id,),
                ).fetchone()
        return int(row["n"]) if row is not None else 0

    def create_player(self, comp_id: str, display_name: str,
                      display_name_norm: str, join_code_hash: str,
                      join_code_expires_at: float,
                      join_code_plain: Optional[str] = None) -> Optional[PlayerRecord]:
        player_id = uuid.uuid4().hex
        now = time.time()
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO players (player_id, competition_id, display_name, "
                    "display_name_norm, status, join_code_hash, join_code_plain, "
                    "join_code_expires_at, joined_at) "
                    "VALUES (?, ?, ?, ?, 'invited', ?, ?, ?, ?)",
                    (player_id, comp_id, display_name, display_name_norm,
                     join_code_hash, join_code_plain, join_code_expires_at, now),
                )
            except sqlite3.IntegrityError:
                self._conn.rollback()
                return None
            self._commit()
        return self.get_player(player_id)

    def get_player(self, player_id: str) -> Optional[PlayerRecord]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM players WHERE player_id = ?", (player_id,)
            ).fetchone()
        return None if row is None else self._player_from_row(row)

    def get_player_by_box(self, box_id: str) -> Optional[PlayerRecord]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM players WHERE box_id = ?", (box_id,)
            ).fetchone()
        return None if row is None else self._player_from_row(row)

    def get_player_by_join_hash(self, code_hash: str) -> Optional[PlayerRecord]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM players WHERE join_code_hash = ?", (code_hash,)
            ).fetchone()
        return None if row is None else self._player_from_row(row)

    def find_active_player_by_name(self,
                                   display_name_norm: str) -> Optional[PlayerRecord]:
        """The player currently competing under this normalized name, if any.

        "Competing" means an invited/running slot in a **live** competition.
        Used to keep one person to one competition at a time even when they
        clear their player cookie or switch browsers.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT p.* FROM players p JOIN competitions c "
                "ON c.id = p.competition_id "
                "WHERE p.display_name_norm = ? "
                "AND p.status IN ('invited', 'running') "
                "AND c.status = 'live' "
                "ORDER BY p.joined_at DESC LIMIT 1",
                (display_name_norm,),
            ).fetchone()
        return None if row is None else self._player_from_row(row)

    def list_players(self, comp_id: str) -> list:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM players WHERE competition_id = ? "
                "ORDER BY joined_at ASC", (comp_id,),
            ).fetchall()
        return [self._player_from_row(r) for r in rows]

    def update_player(self, player_id: str, **fields) -> None:
        allowed = {"status", "join_code_hash", "join_code_plain",
                   "join_code_expires_at", "started_at",
                   "ends_at", "finished_at", "box_id", "claim_url", "claim_uid",
                   "claim_ticket", "claim_expires_at", "claim_error",
                   "claim_attempts", "claim_last_attempt_at",
                   "claim_last_poll_at", "display_name", "display_name_norm"}
        sets, vals = [], []
        for k, v in fields.items():
            if k not in allowed:
                continue
            sets.append(f"{k} = ?")
            vals.append(v)
        if not sets:
            return
        vals.append(player_id)
        with self._lock:
            self._conn.execute(
                f"UPDATE players SET {', '.join(sets)} WHERE player_id = ?", vals
            )
            self._commit()

    def set_player_claim(self, player_id: str, url: Optional[str],
                         uid: Optional[str] = None, ticket: Optional[str] = None,
                         expires_at: Optional[float] = None) -> None:
        self.update_player(player_id, claim_url=url, claim_uid=uid,
                           claim_ticket=ticket, claim_expires_at=expires_at)

    def bind_player_box_atomic(self, code_hash: str, box_id: str,
                               public_key: str, scenario_name: str,
                               scenario_version: int,
                               duration_s: Optional[int] = None,
                               now: Optional[float] = None):
        """Bind a box to an invited player and start the run.

        Returns (status, player, competition). status is one of:
        ok | unknown_code | expired_code | not_live | full | scenario_mismatch
        | already_joined | duplicate_box.
        """
        now = time.time() if now is None else now
        with self.atomic():
            player = self.get_player_by_join_hash(code_hash)
            if player is None:
                return "unknown_code", None, None
            comp = self.get_competition(player.competition_id)
            if comp is None:
                return "unknown_code", None, None
            if player.status not in ("invited",) or player.box_id:
                return "already_joined", player, comp
            if player.join_code_expires_at is not None and player.join_code_expires_at < now:
                return "expired_code", player, comp
            if comp.status != "live" or not comp.join_open:
                return "not_live", player, comp
            if comp.scenario_name != scenario_name or comp.scenario_version != scenario_version:
                return "scenario_mismatch", player, comp
            duration = comp.duration_s if duration_s is None else duration_s
            ends_at = now + duration
            try:
                self._conn.execute(
                    "INSERT INTO boxes (box_id, public_key, scenario_name, "
                    "scenario_version, enrolled_at, last_seq, last_boot_id, t0, "
                    "competition_id, player_id) VALUES (?, ?, ?, ?, ?, 0, NULL, ?, ?, ?)",
                    (box_id, public_key, scenario_name, scenario_version, now,
                     now, comp.id, player.player_id),
                )
            except sqlite3.IntegrityError:
                return "duplicate_box", player, comp
            self._conn.execute(
                "UPDATE players SET status = 'running', started_at = ?, ends_at = ?, "
                "box_id = ?, join_code_hash = NULL, join_code_plain = NULL, "
                "join_code_expires_at = NULL WHERE player_id = ?",
                (now, ends_at, box_id, player.player_id),
            )
            self._conn.execute(
                "INSERT OR REPLACE INTO player_boxes (player_id, box_id, bound_at, "
                "unbound_at, reason) VALUES (?, ?, ?, NULL, 'join')",
                (player.player_id, box_id, now),
            )
            self._conn.execute(
                "UPDATE boxes SET t0 = ? WHERE box_id = ?", (now, box_id),
            )
            player = self.get_player(player.player_id)
            return "ok", player, comp

    def finish_player(self, player_id: str, now: Optional[float] = None) -> None:
        now = time.time() if now is None else now
        self.update_player(player_id, status="finished", finished_at=now,
                           ends_at=now)

    def set_player_status(self, player_id: str, status: str) -> None:
        self.update_player(player_id, status=status)

    def remove_player(self, player_id: str) -> None:
        player = self.get_player(player_id)
        if player is None:
            return
        with self._lock:
            if player.box_id:
                self._conn.execute(
                    "UPDATE player_boxes SET unbound_at = ?, reason = 'removed' "
                    "WHERE player_id = ? AND box_id = ? AND unbound_at IS NULL",
                    (time.time(), player_id, player.box_id),
                )
            self._conn.execute(
                "UPDATE players SET status = 'removed', join_code_hash = NULL "
                "WHERE player_id = ?", (player_id,),
            )
            self._commit()

    # --- admin sessions / audit --------------------------------------------

    def create_admin_session(self, session_hash: str, username: str,
                             csrf_token: str, expires_at: float) -> None:
        now = time.time()
        with self._lock:
            self._conn.execute(
                "INSERT INTO admin_sessions (session_hash, username, csrf_token, "
                "created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                (session_hash, username, csrf_token, now, expires_at),
            )
            self._commit()

    def get_admin_session(self, session_hash: str) -> Optional[AdminSessionRecord]:
        now = time.time()
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM admin_sessions WHERE session_hash = ? AND expires_at > ?",
                (session_hash, now),
            ).fetchone()
        if row is None:
            return None
        return AdminSessionRecord(
            session_hash=row["session_hash"], username=row["username"],
            csrf_token=row["csrf_token"], created_at=row["created_at"],
            expires_at=row["expires_at"],
        )

    def delete_admin_session(self, session_hash: str) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM admin_sessions WHERE session_hash = ?", (session_hash,)
            )
            self._commit()

    def purge_admin_sessions(self) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM admin_sessions WHERE expires_at <= ?", (time.time(),)
            )
            self._commit()

    def add_audit(self, actor: str, action: str,
                  competition_id: Optional[str] = None,
                  player_id: Optional[str] = None,
                  details_json: Optional[str] = None,
                  remote_addr: Optional[str] = None) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit_log (ts, actor, action, competition_id, player_id, "
                "details_json, remote_addr) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (time.time(), actor, action, competition_id, player_id,
                 details_json, remote_addr),
            )
            self._commit()

    def list_audit(self, limit: int = 200) -> list:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [AuditRecord(
            id=r["id"], ts=r["ts"], actor=r["actor"], action=r["action"],
            competition_id=r["competition_id"], player_id=r["player_id"],
            details_json=r["details_json"], remote_addr=r["remote_addr"],
        ) for r in rows]

    # --- engine/server.py: persisted server_secret (§4) ---------------------

    def get_meta(self, key: str) -> Optional[str]:
        with self._lock:
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
            self._commit()
