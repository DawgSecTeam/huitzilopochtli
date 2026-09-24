# Ranked-mode testing round — 2026-09-23

## Round 3 — adversarial, SLA/adversary-live and chaos round (same day)

Five Sonnet 5 subagents, each on its own stage, reporting findings only; every
finding was reproduced by hand before being fixed, and every fix carries a
regression test that fails without it. Engine on a `base-ubuntu24.04` clone
(cadence 30s), four full clones of 112, each `compile` → `plant` → `install
--admin-token`, all enrolled at Total 0. G3/G4 ran the new fixture
`boxes/static-pine-radio/scenario.ranked-r3.yaml`: the ranked box plus an
`atd_sla` SLA check and a 3-event adversary pool (`drop_inert_artifact`,
`kill_service atd`, `flush_firewall`), the first time any live directive
beyond `drop_inert_artifact` ran on a real box.

| Stage | Who | Result |
|---|---|---|
| Baseline suite / two-VM tier | me | 799 passed; `test_ranked_two_machines.py` **unblocked and green** (see test fixes) |
| Honest play (G1) | S1 | predicted 80 → final 80. Every step, including a cron penalty (-10, restored), a wrong forensics answer (no change) and a regression (-5, redone), landed within ≤2 cadences; leaderboard, `scores` table and `huitz score` never disagreed |
| Cheater with root (G2) | S2 | 21 attacks. Forged evidence signed with the box key reaches a full score, **as §3/§2 invariant 6 accept**. Identity/key binding, token single-use, replay/rewind, scenario-version gate, Box header, admin auth (`compare_digest`), leaderboard SQLi and manifest-only `engine_url` all held. No answer key anywhere on the box or in any response |
| SLA + adversary live (G3) | S3 | PASS on all 6. Each directive fired once inside its window (one late only because the engine was down); no re-execution across agent restart or reboot; SLA DOWN/UP obeyed hysteresis 2/2, no back-pay; penalty landed and lifted in the same bundle; only egress was the engine socket (`ss -tnp`); +2h box clock step moved nothing (receipt clock only) |
| Chaos (G4) | S4 + me | Engine SIGKILL, 410s nft partition, agent `kill -9`, box reboot, 3 more kills at arbitrary moments: every box `last_seq == COUNT(checkins)`, contiguous, no dupes; queue flushed 11 bundles in order; T0 and the adversary schedule survived restarts (secret persisted in `engine_meta`). Rubric re-upload moved the point-in-time score 40 → 42 → 40 on the next check-in, SLA untouched |
| Wire/doc audit (local) | S5 | 10 findings, below |

**Fixed (each with a regression test):**
1. *Agent dropped the current bundle when a stale queued one was permanently
   rejected* (`agent/transport.py`): the flush re-raised, losing the current
   cycle's evidence after its seq was already persisted. The flush now drops
   the dead entry and carries on.
2. *Admin rubric upload accepted SLA blocks that 500 every check-in*
   (`common/schema.py`): an unknown key (`hysteresis_fal_n`) passed validation,
   then crashed `SlaParams(**sla)` on every check-in for the scenario; and
   `hysteresis_*_n: 0` pinned an always-UP box DOWN. Unknown keys and
   non-positive counters are now rejected, and `compile` rejects unknown `sla`
   keys, which it used to drop silently.
3. *Adversary fire times depended on pool position* (`engine/adversary_oracle.py`):
   one RNG stream consumed in list order meant adding or reordering an event
   in a re-upload rescheduled every other unfired event. The seed is now
   per-event `(server_secret, box_id, event_id)` (architecture §12 updated).
   Unfired events on a live engine re-roll once at upgrade.
4. *Out-of-range ints 500'd* (`engine/server.py`): seq ≥ 2⁶³ (found live from
   the cheater box) OverflowError'd at the SQLite bind; negative seq was
   accepted into the seq guard. Wire ints are now bounded to 0..2⁶³−1 → 400.
5. *Unauthenticated 500 via deep nesting* (`engine/server.py`): ~3000-deep
   `raw` RecursionError'd in `canonicalize()` before the signature check.
   `raw` deeper than 64 is now a 400.
6. *Version-mismatch 409 lacked `last_seq`* (`engine/checkin.py`), contrary
   to §14.2's "every 409 carries it"; also corrected a stale step-order
   docstring.
7. *Ranked installs kept the honor re-grade timer* (`boxbuilder/providers/ssh.py`):
   every static-pine clone is honor-sealed, so its timer survived a ranked
   install and kept restarting a stopped ranked agent. Ranked installs now
   disable and remove it (verified live on G2).

Fixes 4, 5 and 7 were re-verified live: the redeployed engine returns 400
for the cheater's seq=2⁶³ and a 900-deep `raw`, and the reinstalled G2 has no
timer while its seq kept advancing. Fixes 1–3 and 6 are covered by their
regression tests only.

**Test-harness fixes:** `test_ranked_two_machines.py` now binds the engine to
`0.0.0.0`, detaches with `setsid … < /dev/null`, and regenerates each clone's
machine-id (`proxmox_helper.regen_machine_id`). Template 106 still carries a
stale machine-id, so its two clones and any other live 106 clone collided on
10.0.0.116; the test comment claiming the template was fixed referred to the
long-gone 9106. `test_concurrent_enroll_single_token_exactly_one_winner`'s
client timeout was raised from 30s to 120s: five Ed25519 verifies under one
GIL exceed 30s on a loaded host, which flaked the baseline.

**Known issues surfaced, not fixed (need a decision):**
- **§14.3 rubric versioning is not implemented.** `scenarios` is keyed by name
  only and the uploaded record's `scenario_version` is never compared with the
  box's. Verified live: uploading a v2 record re-scored the enrolled v1 boxes
  against it with no error. The doc says the engine scores against the rubric
  version matching the manifest. Either store per-version rubrics, reject
  mismatched check-ins, or amend the doc.
- **Idle connections hold `MAX_CONNS` slots for 30s** (`Handler.timeout`,
  hardcoded, not env-tunable). Bounded under the friendly-leaderboard threat
  model; make it configurable if ranked ever faces hostile networks.
- **`Transfer-Encoding: chunked` reads as an empty body** → generic 400. Not
  smuggle-able (HTTP/1.0, connection closed per response); the agent never
  sends chunked bodies.
- **A root player can burn their own seq space** (jump to 2⁶³−1, after which
  every later seq is a 400). Self-inflicted only, and it can't touch other boxes.
- engine#8 (penalty docking from `fire_time`) is still unimplemented and was
  observed live: the atd penalty and SLA DOWN bit ~45s after the kill,
  gated by hysteresis, not from `fire_time`.

**Process notes:** Sonnet agents ran out of their session limit near the end;
I finished S4's steps 5–8 by hand. The auto-mode classifier denied S4's
`rm`/`sed -i` remediations on its disposable VM, so it scored through the
forensics answers file instead. The sandbox classifier doesn't know which
hosts are disposable, which matters for future player-style rounds. S4's
"only 3 bundles queued during the partition" was a false positive: 11 were
queued and flushed (seqs 38–48).

---

## Round 2 — 4-guest ranked competition (same day)

Second round on `feature/ranked-mode`: a live 4-team competition plus the
honor-regression proof, driven by one subagent per guest box.

**Honor regression proof** (this round's ranked changes share the zipapp,
authoring validator, sync-report and boxbuilder staging with honor boxes):
- Compile matrix: all 7 honor boxes compile green under the new
  boolean-trap validation — the shipped `permission` checks using
  `equals: false` on boolean `exists` evidence remain correctly exempt.
- Full suite: 798 passed / 1 skipped / 5 deselected.
- Live honor E2E: `pytest -m proxmox
  tests/proxmox/test_local_honor_distribution.py` passed (2/2) — honor
  `.pyz` on real Ubuntu + Fedora clones via guest-exec, `Total: 10` asserted.
  (`.env`'s stale `TEST_TEMPLATE_VMID_UBUNTU=9106` updated to 106.)

**Competition**: static-pine-radio ranked variant; engine VM (cadence 30s) +
4 guest full-clones of 112, each `boxbuilder plant` (re-anchors the at-job →
clean 0 baseline despite the known at-fuse defect) + `install --admin-token`
(one token per guest, 4 distinct box_ids, all enrolled at Total 0). Four
general-purpose subagents then played their teams over SSH in parallel:

| team | strategy | predicted | final | rank |
|---|---|---|---|---|
| A | forensics 4/4 + all 16 evictions | 190 | **190** | 1 |
| B | the 8 EASY evictions only | 40 | **40** | 3 |
| C | 3 MODERATEs, then stopped cron | 20 | **20** | 4 |
| D | forensics only | 40 | **40** | 2 |

Every team landed exactly on target. Engine-side assertions: the B/D tie at
40 broke deterministically by first-confirmation (D before B); each box's
`last_seq == checkins` row count (30/30, 30/30, 29/29, 29/29) — zero lost or
replayed check-ins under 4-way concurrent load; Team C's cron penalty applied
engine-side exactly once (−10); zero tracebacks/errors in the engine log.
Teams confirmed their on-box `huitz score` matched the engine throughout.

Notable: Team D found the planted authorized_keys key on **stationlead**
itself, not on tapeops as a casual reading might assume — the forensics
answer discovery flow works as designed. Provisioning gotchas hit: spec
copies in /tmp resolve relative paths against /tmp (keep generated specs
next to the box dir or use absolute paths), and `boxbuilder plant` defaults
to `./artifacts` unless `--out` is passed.

---

# Round 1

Round report for the first extensive test of ranked mode (branch
`feature/ranked-mode`). Honor mode was considered stable going in; ranked mode
had ~3 loopback integration tests with its restart/crash-recovery sections
commented out, a blocked two-VM tier, and zero real-VM runs. This round built
the automated suites, ran ranked mode end-to-end on real Proxmox VMs, and
fixed everything found. Companion reading: `TESTING_GUIDE.md` §3 (manual
ranked flow), `PLAN.md` (dispositioned ledger), `architecture.md` (source of
truth).

## What the round added

**Automated tiers** (all green; see `tests/`):

| Suite | Covers |
|---|---|
| `tests/integration/test_ranked_loopback.py` | re-enabled: restart-without-re-enroll + SIGKILL-mid-checkin seq recovery (PLAN #50); plus enroll/SLA/queue-flush flows |
| `tests/integration/test_ranked_protocol_errors.py` (34) | the whole wire surface: enrollment error paths (unknown 400 / consumed 409 / expired 410 / scenario mismatch 400 / duplicate box 409 / bad sig 403), check-in check order (box 403 → schema/agent 400 → sig 403 → scenario 400/409 → seq 409), replay + last_seq echo, answer-key redaction asserted on raw response bodies, hostile payloads (oversized Content-Length, non-JSON, JSON array, string/float/NaN seq + wall claims), Box-header tripwire, admin surface (non-ASCII token, NaN/inf/0 ttl, invalid rubric, disabled 503), GET routing |
| `tests/integration/test_ranked_resilience.py` (3) | engine-restart persistence (scores/seq/T0 survive; box resumes), verify-gate 503 backpressure under a 4-box simultaneous volley + retries land + deterministic leaderboard tie-breaks, 5-way token-enroll race (exactly one winner) |
| `tests/integration/test_ranked_adversary.py` (2) | directive fires in window → `drop_inert_artifact` lands in the sandboxed dir → issued exactly once (engine log + box record) → deduped across issued_directives resends AND agent restarts; SLA DOWN + accrual freeze when the monitored service dies |
| `tests/integration/test_zipapp.py` (new test) | the built `.pyz` in ranked mode with a real signed manifest: enrolls, checks in at the engine cadence, renders the engine-authoritative score |

**Real-VM E2E** (both tiers done live, engine as a separate VM host):

- *Smoke*: engine on `base-ubuntu24.04` clone (`HUITZILOPOCHTLI_BIND=0.0.0.0`),
  agent as `.pyz` on a second clone, enroll → check-ins → leaderboard → SLA
  accrual (UP, +points) → engine killed mid-run → agent queues → engine
  restarted → queue flushes contiguously, score continues at the SLA cap →
  tampered signature over the network → 403. Rubric re-upload takes effect on
  the very next check-in.
- *Fidelity*: `boxbuilder compile` + `install --admin-token` against a
  full-clone of the static-pine-radio template (vmid 112) with a ranked
  variant spec (`boxes/static-pine-radio/box.ranked.yaml` +
  `scenario.ranked.yaml`): scenario uploaded to the engine, token minted,
  `/opt/.huitzilopochtli` sealed 700 root with **no rubric / .score.dat /
  engine_record on the box**, systemd long-running unit, motd banner,
  check-ins on the leaderboard, real hardening moved the score 10 → 15, and
  `huitz score` renders the engine-authoritative board as the player.

**Reachability correction**: the dev host CAN reach clone IPs on arbitrary
ports (curl/ssh to 10.0.0.x verified this round); the "VM ports TCP-RST" notes
in `tests/README.md` and the proxmox-ops skill describe a stale or narrower
failure. `test_ranked_two_machines.py`'s blocker #3 is likely obsolete —
retest rather than assume. (Its engine proc also needs
`HUITZILOPOCHTLI_BIND=0.0.0.0` added post-default-loopback.)

## Bugs found and fixed this round

1. **String/float seq and NaN accepted or 500'd** (`engine/server.py`):
   `_bundle_from_dict` did no type validation — a float `seq` of 2.5 was
   scored and stored (corrupting the seq guard), NaN sailed into the audit
   log, and a string `seq` fell out as a 500. All bundle fields are now
   validated at the wire layer (strict ints excluding bool, finite floats,
   non-empty strings, `raw` an object) → clean 400.
2. **Check-in cadence conflated with SLA granularity** (`engine/checkin.py`):
   `next_checkin_s = min(SLA interval_s, default 60)` made 1s-interval rubrics
   spin boxes (seconds of Ed25519 per cycle), froze scoreboard updates for
   3600s-interval rubrics, and gave SLA-less scenarios a 60s cadence that
   delayed directives past any reasonable window (found live: an adversary
   directive due at t0+2s never arrived in a 30s run). Cadence is now
   `HUITZILOPOCHTLI_CHECKIN_INTERVAL_S` (default 60, matching honor's 60s
   re-grade); SLA accrual is elapsed-based + capped, so it is cadence-neutral.
3. **YAML 1.1 boolean trap in file_regex expects** (`authoring/validate.py`):
   `equals: no` compiles to `equals: false` and never matches string evidence
   — the box scores 0 forever, silently. Reproduced live with THE canonical
   sshd hardening (`PermitRootLogin no`). Now an authoring-time error for
   `file_regex` checks (their evidence is always a string); permission checks
   are exempt because their `exists` evidence is genuinely boolean and shipped
   boxes correctly match `equals: false` there.
4. **Player console blind in ranked mode** (`agent/__main__.py`):
   `_sync_desktop_copies` ran only on the honor path and the unit's
   ExecStartPost fires before the first check-in exists — with the install dir
   0700 root, `huitz score` could never find a grade on a box that was
   actively scoring. The ranked loop now publishes the mirror per check-in.
5. **Author-time matcher/evidence field mismatch still silent (partial)**: an
   `http_uptime` expect without `field: status` silently reads the default
   `matched` key and the SLA sits DOWN forever (hit live, fixed in the
   scenario). The engine behaves correctly; the residual gap is authoring UX —
   see backlog.

Also fixed en route: Box-header tripwire (sent by both agent calls, never read
— now a mismatch is a 400), plain-HTTP engine_url warning (non-loopback),
stale `enrollment.py` docstring, `_warn_if_plain_http` tolerant of manifests
without `engine_url`.

## Known issues needing a decision (not fixed here)

- **static-pine-radio at-job fuse (SHIPPED honor box affected)**: the plant is
  `at now + 2 days` anchored at seal time (2026-09-21). It fired 2026-09-23,
  so every clone of template 112 now boots with an empty `atq` and
  self-awards the 10-point `at_queue_emptied` check (reproduced on a fresh
  clone: leaderboard showed 10 before any hardening). The seal-time "Total 0
  baseline" validation predated the fuse. Recommended fix: re-anchor `WHEN`
  far out (e.g. `now + 30 days`) and re-seal, or re-arm the at-job at boot;
  the paired check could also score on the spool file rather than `atq`.
  Needs a replant/reseal round — Hamza's call (shipped template + pool).
- **Adversary penalty docking (engine#8)**: architecture §11.4/§12.1 say the
  engine docks penalties from `fire_time`; the code issues directives
  (at-least-once as of this round) but applies no outage floor. Directive
  execution still costs points indirectly (a killed service fails its own
  SLA check). Implement in the next ranked round or amend the doc.
- **TLS everywhere (agent#11 remainder)**: plain HTTP is warned but allowed;
  the agent uses `ssl.create_default_context()`, so a self-signed engine cert
  fails verification. A ranked deployment story needs a CA/pinning decision
  plus an engine systemd unit + docs (none exist).

## Backlog for the next ranked round

1. Type-aware authoring validation: a per-check-type raw-evidence schema
   (file_regex → `{matched: str}`, http_uptime → `{status: int}`,
   permission → `{exists: bool, ...}`) would have caught both the boolean
   trap and the field-mismatch trap at author time.
2. Engine deployment story: systemd unit + hardening (the engine currently
   runs via nohup; env-only config), plus a documented backup/restore for the
   sqlite DB and the `HUITZILOPOCHTLI_SERVER_SECRET` rotation caveat
   (rotating re-schedules every box's adversary events — see the CAUTION in
   `engine/adversary_oracle.py`).
3. `tests/proxmox/test_ranked_two_machines.py`: unblock (reachability now
   proven) and add `HUITZILOPOCHTLI_BIND=0.0.0.0`; consider making it the
   nightly canary.
4. X-HUITZILOPOCHTLI-Box: now a tripwire; decide whether to formally document
   it in §14 or strip it from the agents.
5. `scores` PK is `box_id` alone — one scenario per box. Multi-scenario boxes
   need a composite key.
6. architecture.md doc gaps (noted, not written — the file was being edited
   concurrently): §14.1 enroll example lacks `scenario_version`; §11.1/§11.2
   omit `/admin/scenarios`, `/admin/tokens`, the `scenarios` + `engine_meta`
   tables, and the verify-gate/503 + connection-cap behaviors.
7. Multi-scenario leaderboard stress + engine backup/restore drill; optional
   adversarial suite (fuzzed bundles at volume) once TLS exists.

## Environment notes for reproducing the VM round

- Templates: `base-ubuntu24.04` (vmid 106) has a **duplicated machine-id** —
  two clones DHCP-collide on one IP. Regen in the clone
  (`rm /etc/machine-id /var/lib/dbus/machine-id && systemd-machine-id-setup`,
  then stop/start) or fix the template. The old `TEST_TEMPLATE_VMID_UBUNTU=9106`
  in `tests/proxmox/.env` is stale (9106 no longer exists).
- Engine runtime on a VM: `common/` + `engine/` tarball, Python 3.12,
  `HUITZILOPOCHTLI_BIND=0.0.0.0`, ~88 KB bundle. Guest-agent file-write needs
  the target dir to exist; a `nohup … &` inside guest-exec must redirect ALL
  fds (use `setsid nohup … > log 2>&1 < /dev/null &`) or the exec call hangs.
- `--provider-host` on boxbuilder's CLI is ignored when `--spec` is given —
  put the IP in the spec (known gotcha, hit again this round).
