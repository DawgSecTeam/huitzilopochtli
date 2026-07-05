# Dawgscore/Huitzilopochtli — Architecture & Implementation Specification

**Status:** decision-complete design spec. Every architectural fork in this document is resolved; sections marked *Non-goal* or *Open* are intentionally out of scope.
**Audience:** the engineer/agent implementing the tool. This document is the source of truth for component contracts and their interactions. Where this document and intuition disagree, follow this document or raise the conflict.
**One-line mental model:** *identical collector everywhere; the only two knobs are where the evaluator runs and where the rubric (answer key) lives.*

---

## 1. Purpose & Scope

DAWGSCORE is a self-contained security-hardening scoring engine in the lineage of CyberPatriot (point-in-time hardening checks) and eCitadel/CCDC (continuous SLA + live adversary). It serves two distinct use cases:

- **Take-home / honor mode** — offline, self-paced boxes distributed after workshops. No network required. The person being scored is trusted (cheating only cheats themselves).
- **Ranked / live mode** — an always-on external engine aggregates scores from boxes during intensive individual practices, supports timed scenarios and a live adversary, and keeps the answer key off the box.

The engine must be **portable**: it assumes no specific infrastructure (no mesh VPN, no particular reverse proxy, no orchestration platform). Its only ranked-mode assumption is outbound network reachability from box to a single engine endpoint.

## 2. Design Principles (Invariants)

These are load-bearing. Violating one breaks the architecture.

1. **Collect/evaluate split.** The on-box collector gathers *facts* and makes **no scoring decisions**. Scoring is a pure function of `(evidence, rubric, clock)`. This is what lets the same code run offline and online by relocating the evaluator.
2. **Checks emit structured evidence + a human reason, never a bare boolean.** The verdict is computed by the evaluator from evidence, not asserted by the collector. This is what makes ranked mode possible and reports explanatory.
3. **Offline is untimed.** All temporal scoring (SLA drip, adversary schedule) exists **only** in ranked mode, where the engine supplies a trusted clock. The box's claimed wall-clock time is diagnostic only and never a scoring input.
4. **The box is never trusted to hold the answer key in ranked mode.** The rubric (expected values + points) lives only on the engine. The box receives a manifest that says *what to collect*, never *what is correct*.
5. **The box is stdlib-only, pure-Python.** No third-party dependency runs on target. Shared crypto is vendored. This is what makes the zipapp portable.
6. **Signing protects identity and transit integrity, not fact-honesty.** In ranked mode a root user can lie about facts; nothing in this design prevents that (see §3). The signature proves *which* box sent a bundle and that it was not altered in flight.
7. **The adversary is structurally incapable of arbitrary outbound network activity.** Its action API is a closed allowlist. No scenario can author a real callback.

## 3. Trust Model & The Honest Ceiling

State this in user-facing docs; do not let it be implied.

| Mode | Evaluator runs on | Rubric lives on | Clock | Timed? | Adversary? | Trust of the reported score |
|---|---|---|---|---|---|---|
| **Honor** | box | box (ships with manifest) | none | no | no | Self-verified. Cheating is self-harm. No anti-tamper. |
| **Ranked** | engine | engine only | engine (authoritative) | yes | yes | **Signed self-report scored against a hidden rubric.** Attributable and tamper-evident *in transit*. NOT cheat-proof. |

**Ranked-mode ceiling, stated plainly:** because transport is push-only (§14), the engine never reaches the box and therefore cannot independently probe anything. Every fact — file permissions, user lists, *and* service uptime — is self-reported by an agent the operator has root over. The per-box signature does not prove truthfulness. A determined operator with root can make the agent report anything.

**What ranked still buys** over pure offline honor mode, and why it is worth building:
1. The **rubric never touches the box** — the operator cannot read the answers and cannot fake a perfect score without reverse-engineering the agent and forging internally-consistent evidence. This is the primary anti-casual-cheat lever.
2. **Trusted clock** — timed scoring cannot be farmed by rolling the box clock.
3. **Central aggregation / leaderboard** across many boxes.
4. **Clean attribution** via per-box identity.

**Do not** stake consequential outcomes (grades, prizes with real value) on ranked scores. It is designed for practice, workshops, and friendly leaderboards.

## 4. Terminology

- **Agent / Collector** — the on-box program (`.pyz`) that collects facts, and in honor mode also scores and reports.
- **Engine** — the always-on ranked-mode server.
- **Fact / Evidence** — a structured record of observed system state from one check. Contains no verdict.
- **Manifest** — signed JSON shipped to the box: which facts to collect + display metadata. Contains no expected values.
- **Rubric** — JSON of expected values + point values + SLA parameters. Engine-only in ranked; ships with the box in honor.
- **Scenario** — author-written YAML that compiles into a (manifest, rubric) pair.
- **Bundle** — a signed set of evidence the agent transmits (ranked) or evaluates locally (honor).
- **Check-in** — one ranked-mode request/response cycle: box pushes a bundle, engine returns the authoritative score + directives.
- **Directive** — an instruction the engine returns to the box (currently: adversary actions to execute now).
- **T0** — the engine's receipt time of a box's *first* check-in; the anchor for all timed scoring for that box.

## 5. System Overview

### 5.1 Components

- **Authoring toolchain** (author's machine; may use non-stdlib libs like PyYAML). Compiles + signs scenarios.
- **Common library** (`common/`, pure stdlib, imported by both agent and engine). Holds the schema, canonical serialization, vendored crypto, and **the evaluator** — so scoring logic is byte-identical wherever it runs.
- **Agent** (`.pyz`, on box): check plugin runtime, platform abstraction, evidence assembly, identity, transport client (ranked), local reporter, adversary executor (ranked).
- **Engine** (server): enrollment endpoint, check-in endpoint, SLA ledger, adversary scheduler, storage (SQLite), leaderboard.

### 5.2 The two-knob model

```
                 HONOR MODE                          RANKED MODE
   +-------------------------------+     +-----------------------------------+
   |  BOX                          |     |  BOX                 ENGINE       |
   |  collector --> evidence       |     |  collector --> evidence           |
   |  evaluator (rubric on box)    |     |  sign+push  -------->  evaluator   |
   |     |                         |     |                       (rubric here)|
   |     v                         |     |             <-------  score+       |
   |  local HTML report            |     |  cache+HTML           directives   |
   +-------------------------------+     +-----------------------------------+
```

The collector code path is identical in both. Only the evaluator's location and the rubric's location change.

## 6. Data Model

All types live in `common/schema.py` as stdlib `@dataclass`. No Pydantic (native core, breaks the pure-Python/zipapp constraint). Validation is explicit (see §6.7). All schema objects are serialized as JSON; on-box parsing is stdlib `json` only. `Enum` is `enum.Enum`.

```python
# common/schema.py
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

SCHEMA_VERSION = 1

class Mode(str, Enum):
    HONOR = "honor"
    RANKED = "ranked"

class Category(str, Enum):
    VULN = "vuln"           # positive points for correct hardening
    PENALTY = "penalty"     # negative points for breaking required state
    PROHIBITED = "prohibited"  # negative points for a forbidden state existing

class CollectorStatus(str, Enum):
    OK = "ok"
    ERROR = "error"         # check ran but could not gather (e.g. file missing)
    TIMEOUT = "timeout"     # exceeded per-check timeout
```

### 6.1 CheckSpec (in Manifest — safe to ship to box)

```python
@dataclass
class CheckSpec:
    id: str                     # unique within scenario, e.g. "ssh_no_root"
    type: str                   # registered check-type key, e.g. "file_regex"
    category: Category
    host_id: str                # "localhost" for single-host; supports multi-host
    collect_params: dict        # type-specific: WHAT to read. No expected values.
    display_title: str          # human label for the report
    display_max_points: int     # for UI only; the real points live in the rubric
    timeout_s: float = 5.0
    is_sla: bool = False        # if true, evaluated continuously in ranked mode
```

**Invariant:** `collect_params` must be sufficient to perform collection but must never contain the expected/correct value. Example: a `file_regex` spec carries the target path and the regex *pattern to extract*, but not whether the extracted line is "correct".

### 6.2 Evidence (collector output — no verdict, no points)

```python
@dataclass
class Evidence:
    check_id: str
    check_type: str
    host_id: str
    status: CollectorStatus
    raw: dict                   # collected values, type-specific
    reason: str                 # human-readable description of what was observed
    collected_monotonic: float  # time.monotonic() on box, for local ordering
    collected_wall_claim: float # box wall clock (epoch); DIAGNOSTIC ONLY
```

### 6.3 RubricEntry (engine-only in ranked; on-box in honor)

```python
@dataclass
class SlaParams:
    interval_s: int             # engine-observed accrual interval
    points_per_interval: int
    hysteresis_fail_n: int = 2  # consecutive fails before entering DOWN
    hysteresis_ok_n: int = 2    # consecutive oks before returning to UP
    max_intervals_per_checkin: int = 3  # cap: silence cannot be back-claimed

@dataclass
class RubricEntry:
    check_id: str
    matcher: dict               # type-specific expected-value matcher (§10.2)
    points: int                 # SIGNED; negative for penalty/prohibited
    sla: Optional[SlaParams] = None
```

### 6.4 Manifest (signed, shipped to box)

```python
@dataclass
class Manifest:
    schema_version: int
    scenario_name: str
    scenario_version: int
    mode: Mode
    engine_url: Optional[str]   # ranked only; where the box pushes
    hosts: list[str]            # host_ids present in this scenario
    checks: list[CheckSpec]
    # NOTE: no rubric, no adversary schedule, no seed.
```

### 6.5 Rubric (JSON; engine-held in ranked, ships with box in honor)

```python
@dataclass
class Rubric:
    schema_version: int
    scenario_name: str
    scenario_version: int
    entries: list[RubricEntry]
    # Adversary schedule + seed live in the ENGINE's scenario record only (§12),
    # never in the manifest, never on a ranked box.
```

### 6.6 Scoring result types (evaluator output)

```python
@dataclass
class CheckResult:
    check_id: str
    category: Category
    awarded_points: int
    passed: bool
    reason: str                 # copied/derived from Evidence.reason + matcher outcome

@dataclass
class ScoreBreakdown:
    scenario_name: str
    scenario_version: int
    total: int
    results: list[CheckResult]
    sla_status: list["SlaStatus"]  # empty in honor mode
    computed_at: float          # engine wall time (ranked) or box time (honor)
```

### 6.7 Validation

`common/schema.py` exposes `validate_manifest(obj) -> list[str]` and `validate_rubric(obj) -> list[str]` returning human-readable errors (empty list = valid). Called by the authoring toolchain (fail the build) and by the agent on load (refuse to run on invalid/unsigned input). No silent coercion.

## 7. Canonical Serialization & Signing

Signatures must be computed over identical bytes on both sides.

- **Canonical form** (`common/canon.py`): `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`. No trailing newline. All signed payloads pass through `canonicalize()`.
- **Crypto** (`common/crypto/`): vendored pure-Python **Ed25519** (`ed25519.py`), pinned to a well-known reference implementation, plus a thin `signing.py` wrapper: `keypair()`, `sign(priv, msg_bytes) -> sig`, `verify(pub, msg_bytes, sig) -> bool`.
- **What is signed:**
  - **Scenario manifest** — signed by the *authoring key* (team key). The agent verifies before running.
  - **Every bundle/check-in** — signed by the *box key*. The engine verifies against the enrolled public key.
- **Do not hand-roll field arithmetic.** Pin the vendored implementation and gate CI against published Ed25519 test vectors (§19).

**Transport confidentiality/authenticity** is provided by TLS (stdlib `ssl`) on top of signing, so the box also gets assurance it is talking to the real engine.

## 8. Scenario Authoring & Build Pipeline

Authors write readable YAML; a build step compiles it. The YAML/PyYAML dependency lives *only* here, on the author's machine — never on the box or in the shipped artifact.

**Pipeline (`authoring/compile.py`):**
1. Parse scenario YAML.
2. Validate against schema (`validate_*`). Fail loudly with line-referenced errors.
3. Split into:
   - **Manifest** (public collection instructions + display metadata).
   - **Rubric** (expected values + points + SLA params).
   - **Engine scenario record** (rubric + adversary event pool + RNG seed) — for ranked, uploaded to the engine out of band; never distributed to boxes.
4. Sign the manifest with the authoring private key.
5. Emit artifacts: `manifest.signed.json`, and for honor mode bundle the rubric into the box image; for ranked keep the rubric + engine record engine-side.

**Author-facing scenario YAML (illustrative):**
```yaml
scenario:
  name: "DAWGSEC Linux Fundamentals"
  version: 3
  mode: ranked            # or honor
  engine_url: "https://scoring.example.org"   # ranked only
  hosts: ["localhost"]

checks:
  - id: ssh_no_root
    type: file_regex
    category: vuln
    display: "Disabled SSH root login"
    max_points: 5
    collect:
      path: /etc/ssh/sshd_config
      extract: '^\s*PermitRootLogin\s+(\S+)'
    expect:                # -> rubric only; stripped from manifest
      equals: "no"
      points: 5

  - id: web_sla
    type: http_uptime
    category: vuln
    is_sla: true
    display: "Web service SLA"
    max_points: 60
    collect:
      url: http://127.0.0.1:80
    expect:                # -> rubric only
      status: 200
      body_contains: "DAWGSEC Default Page"
      sla: { interval_s: 60, points_per_interval: 1 }

adversary:                 # -> engine scenario record only; NEVER shipped to box
  seed_source: per_box     # engine derives per-box RNG from (server_secret, box_id)
  events:
    - action: flush_firewall
      window_s: [600, 1200]     # fire at a seeded time within this window
    - action: kill_service
      params: { service: auditd }
      window_s: [1500, 2100]
```

## 9. The Collector (Agent)

Ships as a `.pyz` zipapp. Entry point `agent/__main__.py`. Reads a local config (§9.7) telling it the mode, manifest path, and (ranked) identity store path.

### 9.1 Check plugin system (`agent/checks/base.py`)

```python
class Check(ABC):
    type_key: str                       # e.g. "file_regex"; unique registry key
    @abstractmethod
    def collect(self, spec: CheckSpec, ctx: "PlatformContext") -> Evidence: ...
```

- A **registry** maps `type_key -> Check subclass`. Registration is decorator-based (`@register`) so a new check type is one self-contained file.
- The collector runs all checks **concurrently** (thread pool), each wrapped with its `timeout_s`. A hung check yields `Evidence(status=TIMEOUT)`; it never stalls the run.
- Collect is **read-only** and side-effect-free with respect to the scored system (the adversary is the only component permitted to mutate system state, §12).

### 9.2 Concrete check types (initial set)

| type_key | collects | raw fields | notes |
|---|---|---|---|
| `file_regex` | reads a text file, applies extract regex | `{matched: str\|null, present: bool}` | for sshd_config, app config, etc. |
| `permission` | stat of a path | `{mode: "0640", uid, gid, exists}` | e.g. `/etc/shadow` restrictiveness |
| `user_group` | parses `/etc/passwd`, `/etc/group` | `{users: [...], group_members: {...}}` | backdoor users, `wheel`/`sudo` membership |
| `service_state` | queries init system via platform layer | `{active: bool, enabled: bool}` | see §9.3 |
| `package` | queries package manager via platform layer | `{installed: bool, version: str\|null}` | dpkg/rpm/apk |
| `http_uptime` | GET against localhost (stdlib `http.client`) | `{status: int\|null, body_match: bool, error: str\|null}` | SLA-capable |
| `db_query` | runs a fixed test query on a local socket | `{ok: bool, error: str\|null}` | SLA-capable; DB driver must remain optional/stdlib-friendly — if a pure-Python driver is unavailable for a given DB, this check degrades to a socket-connect probe |

Each check type's evidence schema is fixed and documented alongside its module.

### 9.3 Platform Abstraction Layer (`agent/platform/`)

Only the parts that actually differ across Fedora/Debian/Alpine are abstracted; file/permission/user checks are already distro-agnostic and bypass this layer.

**Detection** (`detect.py`): presence of `/run/systemd/system` → systemd; else presence of `/sbin/openrc` or `rc-status` → OpenRC. Cache the result in a `PlatformContext` passed to every `collect()`.

| Operation | systemd | OpenRC |
|---|---|---|
| service active | `systemctl is-active <svc>` | `rc-service <svc> status` |
| service enabled | `systemctl is-enabled <svc>` | `rc-update show \| grep <svc>` |

| Package query | command |
|---|---|
| dpkg | `dpkg -s <pkg>` |
| rpm/dnf | `rpm -q <pkg>` |
| apk | `apk info -e <pkg>` |

The layer exposes `service_active(name)`, `service_enabled(name)`, `package_installed(name)`. Adding a distro = adding one strategy class; no check code changes.

### 9.4 Evidence bundle assembly

After all checks return, the collector assembles a `Bundle`:

```python
@dataclass
class Bundle:
    box_id: str
    seq: int                    # monotonic per box; replay/dedup key
    boot_id: str                # from /proc/sys/kernel/random/boot_id; detects reboot
    agent_version: str
    scenario_name: str
    scenario_version: int
    evidence: list[Evidence]
    created_wall_claim: float    # DIAGNOSTIC ONLY
```

`seq` is persisted in the identity store and strictly incremented per bundle. `boot_id` lets the engine detect reboots (which reset uptime assumptions).

### 9.5 Transport client — push-only, queue-and-forward (`agent/transport.py`)

**Ranked mode only.** The box always initiates; the engine never connects inward.

- On each cycle the agent builds a bundle, signs its canonical form, and `POST`s to `<engine_url>/checkin` over TLS.
- If the network is unavailable, the signed bundle is **queued to a local append-only file** and retried on the next cycle. The engine deduplicates by `(box_id, seq)` and rejects `seq <= last_seen_seq` (replay protection).
- Queued bundles preserve their original `seq` and evidence; they are flushed in order on reconnect. Because offline windows earn no SLA credit (§11.3), queueing is for correctness/attribution, not for reclaiming lost time.
- The response (§14.2) is applied: cache the authoritative score, update the local report, and execute any adversary directives (§12).

### 9.6 Identity & enrollment (`agent/identity.py`)

**Ranked mode only.**
1. On first boot, generate an Ed25519 keypair. The **private key never leaves the box**; store it in a local identity file (mode `0600`).
2. Read a one-time **enrollment token** provisioned into the box (single-use, short-TTL, engine-generated; low value if leaked because it only authorizes a pubkey binding).
3. `POST <engine_url>/enroll {enrollment_token, box_id, public_key, agent_version}` over TLS.
4. The engine binds `token -> box_id -> public_key`, marks the token consumed, and returns confirmation. Subsequent check-ins are authenticated by the box signature against this public key.

`box_id` is generated at provisioning (UUID) and stored alongside the key.

### 9.7 Local config

A small on-box file (JSON) read at startup: `{ mode, manifest_path, rubric_path (honor only), identity_path (ranked only), report_path, checkin_interval_s (ranked only) }`. No secrets beyond the identity file (which is separate and `0600`).

### 9.8 Local reporter

See §13.

## 10. The Evaluator (Pure Scorer)

Lives in `common/evaluator.py` so honor-agent and engine run **identical** logic. Pure function, no I/O:

```python
def evaluate(evidence: list[Evidence],
             rubric: Rubric,
             clock: "Clock") -> ScoreBreakdown: ...
```

### 10.1 Point-in-time scoring

For each non-SLA rubric entry, match the corresponding evidence's `raw` against the entry's `matcher`, then award `points` per category:
- `VULN`: award `points` (positive) if matched, else 0.
- `PENALTY`: award `points` (negative) if the required state is **broken** (match fails), else 0.
- `PROHIBITED`: award `points` (negative) if the forbidden state **is present** (match succeeds), else 0.

`passed` and a `reason` are recorded per check. Missing/`ERROR`/`TIMEOUT` evidence is scored as "not satisfied" for VULN, and handled explicitly per matcher for PENALTY/PROHIBITED (documented per matcher).

### 10.2 Matchers

Matcher is a small tagged dict evaluated against a check type's `raw`. Initial matchers: `equals`, `not_equals`, `contains`, `regex`, `mode_at_most` (permission bits no looser than X), `user_absent`, `user_present`, `group_members_subset_of`. Each matcher is a pure predicate `(raw: dict) -> (bool, reason: str)` in a matcher registry, keyed and documented.

### 10.3 SLA scoring

SLA entries are **not** scored by the pure point-in-time pass; they are scored statefully by the engine's SLA ledger (§11), which calls into the matcher to decide up/down per check-in. In honor mode there is no SLA (offline is untimed), so SLA entries are ignored by the on-box evaluator.

## 11. The Engine (Server)

Always-on, portable (a plain HTTP service behind TLS; no orchestration assumed). Stdlib-first.

### 11.1 Endpoints

- `POST /enroll` — §9.6.
- `POST /checkin` — the core loop (§14.2).
- `GET /leaderboard?scenario=...` — aggregated scores (§11.4).
- `GET /health` — liveness.

Implementation may use stdlib `http.server` or a thin WSGI server; no heavyweight framework is required. Concurrency via a thread pool. Keep handlers small; push logic into `checkin.py`, `enrollment.py`, `sla.py`.

### 11.2 Storage (`engine/store.py`)

Stdlib `sqlite3` (default, zero-dependency, portable). Optional Postgres backend behind the same interface if scale demands it later (*Open*, not required for v1). Tables:
- `boxes(box_id PK, public_key, scenario_name, enrolled_at, last_seq, last_boot_id, t0)`
- `enrollment_tokens(token PK, scenario_name, expires_at, consumed_at)`
- `checkins(box_id, seq, received_at, bundle_json)` — audit log.
- `sla_state(box_id, check_id, state, consec_ok, consec_fail, last_credited_at, accrued_points)`
- `scores(box_id, scenario_name, total, updated_at)`
- `adversary_log(box_id, event_id, action, issued_at, params_json)`

### 11.3 SLA ledger & hysteresis (`engine/sla.py`)

Per `(box_id, check_id)` the engine maintains a state machine. On each check-in it reads the SLA evidence's up/down (computed by the matcher), then:

**Hysteresis state machine** (parameters from `SlaParams`):
```
UP    --(consec_fail >= fail_n)-->  DOWN
DOWN  --(consec_ok   >= ok_n)  -->  UP
```
Consecutive counters reset on the opposite observation. A single flap does not change state.

**Accrual (engine clock only):**
- On entering/continuing `UP`, credit points for the elapsed engine-observed interval since `last_credited_at`, computed as `floor(elapsed / interval_s)` intervals, **capped at `max_intervals_per_checkin`**. This cap is what prevents a long silence (or a queued-and-flushed backlog) from being cashed in as continuous uptime.
- No credit accrues while `DOWN` or during gaps where the box did not check in.
- `T0` (first check-in receipt) anchors the box's timeline. All timing uses the engine's `received_at`, never the box's `created_wall_claim`.

**Invariant:** the box's self-reported clock never influences accrual. The engine's receipt time is the sole temporal authority.

### 11.4 Leaderboard / aggregation

`GET /leaderboard` returns ranked `scores` rows for a scenario. Point-in-time totals + accrued SLA points + adversary penalties are summed into `scores.total` on each check-in.

## 12. The Adversary

Ranked/live only (offline is untimed, so no adversary offline). **Refinement over earlier drafts:** the box does **not** hold the seed or the schedule. The engine schedules; the box merely executes directives delivered in check-in responses. This keeps future events unknowable to the operator and is the only box-influencing channel consistent with push-only transport.

### 12.1 Engine-side scheduler (`engine/adversary_oracle.py`)

- Per box, derive a deterministic RNG from `(server_secret, box_id)` — reproducible for audit, unguessable to the operator.
- From the scenario's event pool, pick a concrete fire time for each event within its `window_s`, anchored to `T0`.
- On each check-in, if `received_at >= event.fire_time` and the event has not been issued, include it as a **directive** in the response and log it in `adversary_log`.
- The engine **caused** the outage, so it knows the outage floor: it docks SLA/applies the relevant penalty from `fire_time` onward until the box's subsequent self-reports show restoration. (Honest-ceiling caveat from §3 still applies: a root operator can falsely report instant restoration; the engine can only guarantee the outage did not end *before* it was caused.)

### 12.2 Box-side executor (`agent/adversary/`)

- Parses directives from the check-in response and executes them via a **closed action vocabulary** (`actions.py`). The executor can run *only* actions in this allowlist; there is no generic "run command" primitive exposed to scenarios.
- Initial action allowlist (all local, all reversible-by-the-student-as-the-challenge):
  - `flush_firewall` — flush the local packet filter rules.
  - `kill_service <service>` — stop a named service via the platform layer.
  - `drop_inert_artifact <path>` — write a **benign, inert** marker file (never an executable payload, never a callback).
- **Hard constraint (§2.7):** no action may open an outbound connection to any host other than the engine. The action API has no network egress primitive at all. This is enforced structurally (there is no code path for it), not by policy.

## 13. Reporting

Static HTML generated from the machine-readable `ScoreBreakdown` JSON, so report and protocol share one payload. Includes a `<meta http-equiv="refresh" content="N">` so the browser auto-updates. **The refresh interval is display cadence only; it is never a scoring input.**

- **Honor box:** has the rubric, runs the evaluator locally, renders the real score on demand / each refresh.
- **Ranked box:** has no rubric and cannot compute anything. Its dashboard is a **cache of the engine's last response**. Before the first response it shows "submitted — awaiting engine". It clearly labels the number as the engine's authoritative score.

Dashboard elements: cumulative total; table of point-in-time results (category, awarded, reason); SLA status table (state UP/DOWN, accrued); and (ranked) a "last confirmed by engine at <time>" stamp.

## 14. Protocol Specification

All requests over TLS (stdlib `ssl`). All bodies are canonical JSON (§7). All box→engine bodies are signed by the box key; the signature travels in an `X-DAWGSCORE-Sig` header (base64) alongside `X-DAWGSCORE-Box` (box_id).

### 14.1 Enrollment

Request `POST /enroll`:
```json
{ "enrollment_token": "<one-time>", "box_id": "<uuid>",
  "public_key": "<base64>", "agent_version": "1.0.0",
  "scenario_name": "DAWGSEC Linux Fundamentals" }
```
Response `200`:
```json
{ "ok": true, "box_id": "<uuid>", "checkin_interval_s": 60 }
```
Errors: `409` token already consumed; `410` token expired; `400` malformed. This request is signed by the box key; the engine verifies the signature matches the `public_key` in the body (proof of private-key possession).

### 14.2 Check-in

Request `POST /checkin` (body = canonical `Bundle`, §9.4). Headers carry `box_id` + signature.

Engine handler order (fail closed at each step):
1. Look up `box_id` → public key. Unknown box → `403`.
2. Verify signature over the canonical body. Bad signature → `403`.
3. Reject `seq <= last_seq` (replay/dedup) → `409` with `last_seq` so the agent can resync.
4. Stamp `received_at = engine_now()`. If this is the first check-in, set `T0`.
5. Persist the check-in (audit log).
6. Evaluate point-in-time evidence against the engine-held rubric (`common.evaluate`).
7. Update SLA ledger (§11.3).
8. Run adversary scheduler; collect any due directives (§12.1).
9. Update `scores.total`; return the response.

Response `200`:
```json
{
  "server_time": 1730000000.0,
  "score": { "total": 42, "results": [ ... ], "sla_status": [ ... ] },
  "directives": [ { "action": "kill_service", "params": { "service": "auditd" }, "event_id": "e2" } ],
  "next_checkin_s": 60,
  "last_seq": 17
}
```

### 14.3 Versioning

Every bundle and manifest carries `schema_version`, `agent_version`, and `scenario_version`. The engine rejects incompatible `schema_version` with a clear error. An older box and a newer engine reconcile on `scenario_version`; the engine scores against the rubric version matching the box's manifest, or returns `409 scenario_version_mismatch` instructing re-provision.

## 15. Interaction Flows

**Honor-mode run (offline):** agent loads signed manifest → verifies authoring signature → runs all checks concurrently → assembles evidence → loads local rubric → `common.evaluate(evidence, rubric, no-clock)` → writes HTML. No network, no time axis, no adversary.

**Ranked enrollment:** first boot → generate keypair (private key stays) → read one-time token → `POST /enroll` (signed) → engine binds pubkey, consumes token.

**Ranked check-in loop:** every `checkin_interval_s` → collect evidence → assemble+sign bundle (seq++) → `POST /checkin` (TLS) → on success apply score to cache/report and execute directives; on network failure queue bundle and retry next cycle.

**SLA accrual:** each check-in updates the per-check hysteresis state on the engine; while `UP`, capped drip accrues against engine-observed elapsed time; gaps and `DOWN` earn nothing.

**Adversary event lifecycle:** engine derives per-box schedule from `(server_secret, box_id)` → when a fire time is reached at check-in, engine returns a directive and begins docking from that moment → box executes the local action via the closed vocabulary → student remediates → subsequent self-reports show restoration → engine resumes credit.

**Offline queue flush:** box offline for several intervals → bundles queued with preserved seq → on reconnect flushed in order → engine dedups, scores each, but SLA cap prevents the backlog from being cashed as continuous uptime.

## 16. Trust Boundaries & Security Requirements

| Boundary | Guarantee | Non-guarantee |
|---|---|---|
| Box → Engine transit | TLS confidentiality + box-signature integrity | — |
| Box identity | Signature proves which enrolled box sent the bundle | Does not prove the box's facts are true |
| Rubric secrecy (ranked) | Answers never on the box; operator can't read expected values | A root operator can still forge internally-consistent evidence |
| Clock (ranked) | Engine clock authoritative; time cannot be farmed by box | — |
| Adversary egress | Structurally no outbound except to engine | — |
| Enrollment token | Single-use, short-TTL, low value | Should still be delivered over the provisioning channel, not embedded in a shared image |

Requirements:
- Private box key file mode `0600`; never transmitted.
- Engine DB stores only public keys — its compromise does not enable box impersonation.
- Fail closed on every verification step in §14.2.
- The authoring private key is offline/held by the team; only the public authoring key ships (for manifest verification).

## 17. Packaging & Deployment

- **Agent artifact:** Python **zipapp** (`.pyz`), pure-Python/stdlib + vendored crypto. Assumes a Python interpreter is present. **Alpine caveat:** minimal Alpine ships without Python — provisioning must `apk add python3`.
- **Compilation** (PyInstaller/Nuitka) is optional and for packaging convenience only; it is **irrelevant to security** because ranked mode never trusts the box regardless. Note glibc vs musl: a binary built on glibc will not run on Alpine/musl, so prefer the zipapp for portability and only compile per-target if a Python-free box is required.
- **Install:** systemd unit or OpenRC init script that starts the agent at boot. Restricted install dir (e.g. `/opt/dawgscore/`) holding the `.pyz`, signed manifest, config, and (honor) rubric; identity file separate at `0600`.
- **Distribution:** export configured VM as `.ova`/`.qcow2`.
- **Re-arm/reset:** a documented reset path resets local state (seq, identity optional, cached score, report) so a take-home box can be replayed without a full redeploy.
- **Version stamping:** engine and scenario versions on every payload (§14.3).

## 18. Suggested Module Layout

```
dawgscore/
  common/                # pure stdlib; imported by agent AND engine
    schema.py            # dataclasses (§6)
    canon.py             # canonical serialization (§7)
    evaluator.py         # pure scorer (§10) — identical everywhere
    matchers.py          # matcher registry (§10.2)
    crypto/
      ed25519.py         # vendored, pinned
      signing.py         # sign/verify wrapper
    version.py
  agent/                 # ships as .pyz
    __main__.py
    config.py
    collector.py
    checks/ { base.py, file_regex.py, permission.py, user_group.py,
              service_state.py, package.py, http_uptime.py, db_query.py }
    platform/ { detect.py, base.py, systemd.py, openrc.py, pkg.py }
    adversary/ { executor.py, actions.py }   # closed vocabulary
    identity.py
    transport.py         # push client + queue-and-forward
    reporter.py
  engine/
    server.py            # endpoints
    enrollment.py
    checkin.py
    sla.py               # ledger + hysteresis
    adversary_oracle.py  # scheduler
    leaderboard.py
    store.py             # sqlite3
  authoring/             # author machine; may use PyYAML (NOT shipped)
    compile.py           # YAML -> signed manifest + rubric + engine record
    validate.py
    sign_scenario.py
  tests/
    vectors/             # Ed25519 known-answer vectors
```

## 19. Build, Test & CI Requirements

- **Crypto correctness:** CI must run the vendored Ed25519 against published known-answer test vectors on every commit. Pin the implementation's version/hash.
- **Canonical serialization:** round-trip and cross-language-stable byte tests; sign on one process, verify on another.
- **Evaluator determinism:** golden tests mapping `(evidence, rubric) -> ScoreBreakdown`, including PENALTY/PROHIBITED and missing/ERROR/TIMEOUT evidence.
- **Hysteresis + SLA cap:** state-machine unit tests covering flap suppression and the silence/backlog cap.
- **Platform layer:** table-driven tests for systemd vs OpenRC command mapping and package-manager mapping.
- **Zipapp portability:** build the `.pyz` and smoke-run it under the interpreter versions on Debian, Fedora, and Alpine (with `python3` added).
- **Adversary egress:** a test asserting the action API exposes no network-egress primitive.
- **Protocol fail-closed:** tests for each `403/409/410/400` path in §14.

## 20. Non-goals & Open Items

**Non-goals (v1):**
- Cheat-proof ranked scoring (impossible under push-only + root; see §3).
- Engine-initiated probing of boxes (transport is push-only by decision).
- Multi-host *implementation* (schema supports `host_id` now; first build scores single-host).
- Mode conversion (a box's mode is fixed at provisioning; an offline run cannot be promoted to ranked).

**Open items (deferred, not blocking):**
- Optional Postgres storage backend behind the `store.py` interface.
- Additional check types (e.g. sysctl, cron, scheduled-task) and matchers, added via the registries with no core changes.
- Multi-host scenario execution once single-host is proven.
```
