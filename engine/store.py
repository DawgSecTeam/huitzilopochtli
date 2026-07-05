"""SQLite-backed storage. See architecture.md §11.2.

FROZEN — the Store class and record dataclasses below are the contract every
other engine/ module (enrollment.py, checkin.py, sla.py, adversary_oracle.py,
leaderboard.py) is built against. They only need these signatures, not this
file's implementation, so all of engine/ can be built in parallel.

PHASE 1 TASK: implement every method body against a sqlite3 schema covering
the tables in §11.2: boxes, enrollment_tokens, checkins, sla_state, scores,
adversary_log. Do not change method signatures.
"""
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


class Store:
    def __init__(self, db_path: str):
        """Open (creating if absent) the sqlite3 file at db_path and ensure
        the schema exists."""
        raise NotImplementedError

    # --- enrollment.py -----------------------------------------------------

    def get_token(self, token: str) -> Optional[dict]:
        """Returns {"scenario_name": str, "expires_at": float,
        "consumed_at": float | None} or None if the token is unknown."""
        raise NotImplementedError

    def consume_token(self, token: str) -> None:
        raise NotImplementedError

    def create_box(self, box_id: str, public_key: str, scenario_name: str) -> None:
        raise NotImplementedError

    # --- checkin.py ----------------------------------------------------------

    def get_box(self, box_id: str) -> Optional[BoxRecord]:
        raise NotImplementedError

    def set_t0_if_unset(self, box_id: str, t0: float) -> None:
        raise NotImplementedError

    def update_box_seq(self, box_id: str, seq: int, boot_id: str) -> None:
        raise NotImplementedError

    def save_checkin(self, box_id: str, seq: int, received_at: float,
                      bundle_json: str) -> None:
        """Audit log insert into `checkins`."""
        raise NotImplementedError

    def upsert_score(self, box_id: str, scenario_name: str, total: int) -> None:
        raise NotImplementedError

    # --- sla.py --------------------------------------------------------------

    def get_sla_state(self, box_id: str, check_id: str) -> Optional[SlaStateRecord]:
        raise NotImplementedError

    def save_sla_state(self, rec: SlaStateRecord) -> None:
        raise NotImplementedError

    # --- adversary_oracle.py ---------------------------------------------------

    def get_issued_event_ids(self, box_id: str) -> set:
        raise NotImplementedError

    def log_adversary_event(self, box_id: str, event_id: str, action: str,
                             issued_at: float, params: dict) -> None:
        raise NotImplementedError

    # --- leaderboard.py --------------------------------------------------------

    def get_scores(self, scenario_name: str) -> list:
        """Returns list[ScoreRow], ranked descending by total."""
        raise NotImplementedError
