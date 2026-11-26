"""SQLite schema for engine/store.py. See architecture.md §11.2."""

SCHEMA = """
CREATE TABLE IF NOT EXISTS boxes (
    box_id TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,
    scenario_name TEXT NOT NULL,
    scenario_version INTEGER NOT NULL DEFAULT 0,
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
    history_json TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (box_id, check_id)
);
CREATE TABLE IF NOT EXISTS scores (
    box_id TEXT PRIMARY KEY,
    scenario_name TEXT NOT NULL,
    total INTEGER NOT NULL,
    updated_at REAL NOT NULL,
    first_scored_at REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS adversary_log (
    box_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    action TEXT NOT NULL,
    issued_at REAL NOT NULL,
    params_json TEXT NOT NULL,
    fire_time REAL,
    affects_check TEXT,
    restored_at REAL
);

    -- Ensure a directive fires at most once per (box, event).
    CREATE UNIQUE INDEX IF NOT EXISTS idx_adversary_log_box_event
        ON adversary_log (box_id, event_id);

CREATE TABLE IF NOT EXISTS scenarios (
    scenario_name TEXT NOT NULL,
    scenario_version INTEGER NOT NULL,
    rubric_json TEXT NOT NULL,
    adversary_json TEXT NOT NULL,
    uploaded_at REAL NOT NULL,
    PRIMARY KEY (scenario_name, scenario_version)
);

CREATE TABLE IF NOT EXISTS engine_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Ranked competition mode (v1.1). All additive; legacy rows keep NULL
-- competition_id/player_id and retain the pre-competition behavior.
CREATE TABLE IF NOT EXISTS competitions (
    id TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    scenario_name TEXT NOT NULL,
    scenario_version INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft',
    join_open INTEGER NOT NULL DEFAULT 0,
    max_players INTEGER NOT NULL,
    duration_s INTEGER NOT NULL,
    workshop_pool_code TEXT,
    -- The portal pool name this competition provisioned ("huitz-ranked-<slug>").
    -- Stored rather than derived so teardown ownership survives a slug change
    -- and a sibling slug (demo vs demo-2) can never match by prefix.
    workshop_pool_name TEXT,
    -- End automatically once joins are closed and every run has finished
    -- (multi-event hygiene: a forgotten live competition pins a whole pool).
    auto_end INTEGER NOT NULL DEFAULT 0,
    -- Wall-clock time (engine receipt clock) at which the competition ends
    -- itself: every run still in progress stops and the pool is torn down,
    -- exactly as if an admin had pressed End. NULL = not scheduled.
    scheduled_end_at REAL,
    theme_json TEXT,
    join_instructions TEXT,
    leaderboard_hidden INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    started_at REAL,
    ended_at REAL,
    CHECK (status IN ('draft','live','ended'))
);

CREATE TABLE IF NOT EXISTS players (
    player_id TEXT PRIMARY KEY,
    competition_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    display_name_norm TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'invited',
    join_code_hash TEXT,
    join_code_plain TEXT,
    join_code_expires_at REAL,
    joined_at REAL NOT NULL,
    started_at REAL,
    ends_at REAL,
    finished_at REAL,
    box_id TEXT,
    claim_url TEXT,
    claim_uid TEXT,
    claim_ticket TEXT,
    claim_expires_at REAL,
    claim_error TEXT,
    claim_attempts INTEGER NOT NULL DEFAULT 0,
    claim_last_attempt_at REAL,
    claim_last_poll_at REAL,
    -- When this run's VM was released (post-run access window expired or an
    -- admin release). NULL while the box is still out.
    box_released_at REAL,
    -- v1.2 teams: long-lived per-seat link token so any member's browser can
    -- reach the run (the one-time join code binds the box, not the people).
    team_token_hash TEXT,
    team_token_plain TEXT,
    UNIQUE (competition_id, display_name_norm)
);

CREATE TABLE IF NOT EXISTS team_members (
    player_id TEXT NOT NULL,
    handle TEXT NOT NULL,
    added_at REAL NOT NULL,
    PRIMARY KEY (player_id, handle)
);

CREATE TABLE IF NOT EXISTS player_boxes (
    player_id TEXT NOT NULL,
    box_id TEXT NOT NULL,
    bound_at REAL NOT NULL,
    unbound_at REAL,
    reason TEXT,
    PRIMARY KEY (player_id, box_id)
);

-- Multi-box competitions (v1.2). All three tables are additive: a
-- single-scenario competition has exactly one row in each, equal to the
-- mirror columns it also keeps (competitions.scenario_name/_version,
-- players.box_id/claim_*, competitions.workshop_pool_*), so every pre-v1.2
-- reader sees precisely what it saw before.
--
-- The lineup: which scenarios a competition hands out, position-ordered.
-- Entry 0 is the "primary" scenario whose mirrors the legacy columns carry.
CREATE TABLE IF NOT EXISTS competition_scenarios (
    competition_id TEXT NOT NULL,
    scenario_name TEXT NOT NULL,
    scenario_version INTEGER NOT NULL,
    position INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (competition_id, scenario_name)
);

-- Per (seat, lineup entry) bind + claim state; the box's own rubric stays
-- keyed by its enrolled scenario (the boxes table), so nothing here scores.
-- status mirrors the players vocabulary; the clock stays on players (one
-- team clock governs every box of the seat).
CREATE TABLE IF NOT EXISTS run_slots (
    slot_id TEXT PRIMARY KEY,
    player_id TEXT NOT NULL,
    competition_id TEXT NOT NULL,
    scenario_name TEXT NOT NULL,
    scenario_version INTEGER NOT NULL DEFAULT 1,
    box_id TEXT,
    status TEXT NOT NULL DEFAULT 'invited',
    bound_at REAL,
    box_released_at REAL,
    claim_url TEXT,
    claim_uid TEXT,
    claim_ticket TEXT,
    claim_expires_at REAL,
    claim_error TEXT,
    claim_attempts INTEGER NOT NULL DEFAULT 0,
    claim_last_attempt_at REAL,
    claim_last_poll_at REAL,
    UNIQUE (player_id, scenario_name)
);
CREATE INDEX IF NOT EXISTS idx_run_slots_box ON run_slots(box_id);
CREATE INDEX IF NOT EXISTS idx_run_slots_comp ON run_slots(competition_id);

-- Per-scenario pool pins. The pool NAME keeps the exact full stored string
-- as its teardown anchor (one pool per competition-scenario; the legacy
-- huitz-ranked-<slug> name is unchanged whenever there is only one entry).
CREATE TABLE IF NOT EXISTS competition_pools (
    competition_id TEXT NOT NULL,
    scenario_name TEXT NOT NULL,
    pool_code TEXT,
    pool_name TEXT,
    pinned_at REAL,
    PRIMARY KEY (competition_id, scenario_name)
);

CREATE TABLE IF NOT EXISTS admin_sessions (
    session_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    csrf_token TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    competition_id TEXT,
    player_id TEXT,
    details_json TEXT,
    remote_addr TEXT
);
"""
