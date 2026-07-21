# Huitzilopochtli – Current Status

## Completed (merged to `main`)

### 8 Bug Fixes (commit `4142499`, merged as `8e465db`)

| Bug | Description | Fix | Files |
|-----|-------------|-----|-------|
| **1** | Enrollment brick – transient `/enroll` failure permanently bricks box | Retry enroll every boot until `.enrolled` marker exists | `agent/__main__.py` |
| **3** | Body DoS – no cap on request body size | 1 MiB hard cap in `_read_json_body` | `engine/server.py` |
| **4** | ERROR/TIMEOUT scored as DOWN | Only feed SLA ledger on `status == "ok"`; skip ERROR/TIMEOUT | `engine/checkin.py` |
| **5** | scenario_version unenforced | Track version on boxes at enrollment; reject 409 on mismatch | `engine/store.py`, `engine/enrollment.py`, `engine/checkin.py`, `agent/identity.py` |
| **6a** | Adversary pool unvalidated at upload | Validate `window_s` + `action` at `POST /admin/scenarios` | `engine/server.py` |
| **6b** | Ed25519 S-malleability | Reject `S >= l` in `checkvalid` | `common/crypto/ed25519.py` |
| **6c** | `next_checkin_s` hardcoded to 60 | Derive from min SLA interval across rubric entries | `engine/checkin.py` |
| **6d** | Leaderboard leaks `box_id` | Replace `box_id` with `rank` number in public projection | `engine/leaderboard.py` |

### Test Updates
- `tests/integration/test_admin_endpoints.py` – updated for `scenario_version` in enroll body and `rank` in leaderboard
- `tests/integration/test_ranked_loopback.py` – updated for `scenario_version` in enroll, `.enrolled` marker, and `rank` in leaderboard

### Test Results
- **278 tests pass** (254 unit + 24 integration)
- All tests verified on `main` branch

## Remaining Issues

### Known / Acceptable
1. **Pure-Python Ed25519 performance** – each sign/verify takes ~2s. Loopback tests need 10-12s sleep windows. Not a correctness issue; acceptable for v1. Consider switching to `cryptography` library Ed25519 for production.

### Nothing Blocked
All 8 reported bugs are fixed and merged. No open items remain.

## Post-Audit Residuals (branch `fix/post-audit-residuals`)

A re-audit of `main` + the unmerged `origin/hermes-qa/huitzilopochtli/f6fa854` branch surfaced one real residual and three clean cherry-picks from hermes-qa. (Two of hermes-qa's commits were rejected: the boot_id seq reset was a flawed fix for a non-problem — the agent persists `last_seq` to disk across reboots via `agent/identity.py`, so it never restarts seq at 1, and the reset had a replay hole where a late old-session bundle re-triggered it; the NFC normalization commit was a no-op since `json.dumps(default=)` never fires for native `str`.)

| Fix | Description | Files |
|-----|-------------|-------|
| **6a residual** | `_validate_adversary_pool` ValueError was uncaught → HTTP 500; now wrapped → 400 | `engine/server.py` |
| **permission path** | Missing `path` param raised KeyError; now returns structured ERROR evidence | `agent/checks/permission.py` |
| **collector cap** | `max_workers` capped at 20 (was 1:1 with check count) | `agent/collector.py` |

Also committed the dangling `test_ranked_loopback.py` updates (`.enrolled` marker, `scenario_version` arg, leaderboard `rank`) that tracked the audit fixes but were never committed.

### Test Results (on `fix/post-audit-residuals`)
- **281 tests pass** (256 unit + 25 integration), up from 278 baseline (+3 new tests)

## Branches
- `main` – current state with all audit fixes merged
- `fix/audit-24-bugs` – fully merged into `main` (merge-base equals tip; safe to delete)
- `fix/post-audit-residuals` – post-audit residuals + clean hermes-qa cherry-picks (this branch)
- `origin/hermes-qa/huitzilopochtli/f6fa854` – unmerged; partially superseded by main's audit fixes. Useful commits (permission path, collector cap) cherry-picked into `fix/post-audit-residuals`. Not safe to merge whole (lacks all 8 audit fixes; 2 SLA commits strip `update_sla_atomic`; collector commit reintroduces shutdown hang)
