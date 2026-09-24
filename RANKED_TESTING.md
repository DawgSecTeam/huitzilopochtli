# Ranked-mode testing round — 2026-09-23

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
