# Huitzilopochtli 1.0 — release hardening plan

Branch: `release/1.0-hardening`
Baseline: `16c4696` (main)
Goal: fix every confirmed finding from the full-project review, add a regression
test for each, then run the full automated suite plus real end-to-end testing.

Legend: each batch is independently reviewable and must leave `pytest` green.
"Exit" = the checks that must pass before moving on.

---

## Batch 0 — baseline and harness

- Branch created from `main`; untracked Saltmarsh/Windows-vuln assets preserved.
- Record the exact test commands and environment.
- Replace the recursive Ed25519 field exponentiation with the equivalent
  `pow(base, exp, mod)` so the suite becomes practical to run; verify against
  RFC 8032 vectors before using the speed-up as a baseline.

Exit: crypto vectors green; a targeted unit run completes in minutes.

## Batch 1 — scoring integrity (core)

1. **SLA outage back-claim**: on `max_intervals_per_checkin` overflow, credit the
   cap and forfeit the rest of the gap; keep only the sub-interval remainder.
   Tests: long gap + rapid check-ins earns at most the cap; normal fractional
   carry-over still works; DOWN transition still credits nothing.
2. **Matcher validation and evaluator containment**: per-matcher argument
   schemas (field/pattern/value/allowed/username/group/max_mode types, regex
   compile dry-run); `validate_rubric` returns errors instead of raising on
   unhashable ids/tags; `evaluate()` catches a bad entry, scores it unsatisfied
   with a generic reason, and never aborts the whole check-in.
3. **`passed` semantics**: for `prohibited`, `passed` means the required state
   holds (forbidden state absent), so ranked reports no longer say
   "Passed: yes" beside a negative score.
4. **Zero-point / max-points consistency**: authoring rejects a non-SLA check
   with no positive `expect.points`; `max_points` must match the rubric points
   (penalties compare absolute values); board counts a passed zero-point VULN
   as fixed instead of leaving progress permanently short.
5. **SLA parameter validation**: reject NaN/Infinity `interval_s` and other
   non-finite SLA numbers.

Exit: new unit tests for every item, plus the existing evaluator/schema/SLA
suites.

## Batch 2 — cryptography

1. Reject small-order (identity/torsion) and non-canonical Ed25519 public keys
   and R points at verification; enrollment and check-in both inherit it.
2. Add known-answer tests for the identity point, order-2 point, and a
   non-canonical encoding; keep RFC 8032 vectors green.
3. Confirm the `pow()` speed-up is semantically identical.

Exit: crypto + protocol tests; the forbidden key can no longer enroll.

## Batch 3 — authoring and schema

1. Type validation for scenario/check fields (name/version/mode/hosts, id/type/
   display/max_points/collect/timeout_s/is_sla), including unknown keys that
   silently disable a feature (`adversrys:`) and unknown check types.
2. `engine_url` must parse as http(s); ranked requires it.
3. `expect.sla` structure validated at authoring time (missing keys produce a
   clean error, not a KeyError); `is_sla` without `sla` rejected; `sla` without
   `is_sla` still derives `is_sla`.
4. Adversary block validated at compile time: finite non-negative windows,
   explicit stable ids, known action vocabulary, action params shape.
5. `sign_manifest()` strips any existing `_signature` before signing.
6. Readme lint normalizes HTML tags/entities and Markdown emphasis before
   matching, and documents that the allow-list is an explicit review decision.

Exit: authoring/validate/schema/readme tests; every existing box scenario still
compiles.

## Batch 4 — engine protocol and storage

1. `/enroll` rejects non-object JSON with 400; range-check `scenario_version`;
   generic handler-level 500 with no internals.
2. DB file/SQLite artifacts created `0600`; document the sealed parent.
3. Scenario records keyed by `(scenario_name, scenario_version)` with an
   in-place migration; check-in selects the enrolled version and returns 409
   when no matching rubric exists. Bootstrap `/admin/scenarios` validation is
   the same as admin upload.
4. Signature verification happens before rubric lookup/parse; scenario
   existence is not an unauthenticated oracle; parsed rubrics are cached.
5. Cheap pre-verify gates: unknown box lookup, schema/major version, and stale
   seq can reject before expensive verify, with the same fail-closed semantics.
6. Simple per-source rate limit for `/enroll` and `/checkin`; verify-gate
   saturation still returns 503.
7. Leaderboard tie-break uses an immutable first-scored timestamp.
8. Adversary docking: persist `fire_time`, optional `affects_check`, and force
   the mapped SLA DOWN from the check-in after issuance until evidence shows
   restoration. Validate/compile the mapping. If a scenario has no mapping,
   behavior stays as today (indirect SLA cost only), documented in the spec.

Exit: store/checkin/admin/protocol tests, including re-upload v1→v2, migrated
DB, malformed bodies, and docking.

## Batch 5 — agent runtime

1. Per-check timeouts measured from the moment a check starts; queued checks
   are not timed out before running; late results are discarded. Keep the
   bounded concurrency and daemon-thread exit behavior.
2. Directives file: require a JSON list of strings; any other shape fails
   closed. `rearm --reset-identity` deletes `.directives` too.
3. Transport queue: bounded size/age; a bundle that gets repeated 5xx is
   dead-lettered instead of blocking the head forever; oversized bundles are
   shrunk/flagged client-side before hitting the engine 1 MiB cap; fsync queue
   writes.
4. Identity: enforce `0600` on load, fsync+replace, distinguish token-consumed
   from duplicate-box 409, actionable corrupt-identity error.
5. Config: strict booleans (`"false"` is not true), manifest/config mode must
   match, cert/config errors are fatal rather than retried forever, enrollment
   retry has bounded backoff/fatal classification.
6. Ranked report cache survives restart; countdown anchored to box receipt
   time; one honor interval used by HTML and snapshot on every platform.
7. Honor grade concurrency: file lock, atomic report/snapshot writes, baseline
   committed only after successful publication.

Exit: agent/transport/notify tests; a restart shows the last cached score; a
long outage does not wedge the queue.

## Batch 6 — Windows and CLI

1. Windows: guard `os.chown`, UTF-8 (with BOM tolerance) for answers/collector/
   PowerShell/subprocess output, working `kill_service`/`flush_firewall`
   actions, consistent honor interval.
2. CLI: output encoding fallback; control-character sanitisation at the
   terminal boundary; strict accent validation; snapshot schema validation;
   per-question answers paths; full-file reads; BrokenPipe/pager handling;
   unknown flags and malformed ordinals exit 2; width clamp; watch EOF handling.
3. Windows install/CLI unit tests where the code is platform-neutral enough to
   test via mocks; static checks for the PowerShell scripts.

Exit: CLI tests, Windows-support tests, and a real Windows VM if available.

## Batch 7 — boxbuilder and packaging

1. Restore compile-state fingerprints (scenario/config/mode/engine URL) and
   refuse plant/install against stale artifacts; reconcile nakon cache claims.
2. Unconditional install-directory cleanup (root POSIX and Windows) so a
   ranked reinstall cannot inherit `.score.dat`, identity, `.enrolled`,
   `.directives`, queues, or old reports.
3. Artifact hygiene: `0700` artifacts dir, `0600` rubric/engine record/config/
   `.score.dat`/answer keys, deploy config written to a temp file and removed
   after deploy, enrollment token redacted from JSON/kept only in a `0600`
   delivery file.
4. Admin API refuses non-loopback plain HTTP unless explicitly overridden;
   ranked scenarios moved to HTTPS where the engine supports it.
5. SSH provider: host keys rejected by default (explicit opt-in to trust-all),
   stdout/stderr drained concurrently so large command output cannot deadlock,
   numeric validation and `shlex.quote()` for remote output interpolated into
   root commands, `mkstemp`/`O_NOFOLLOW` for key/deploy writes.
6. `build` validates `--image-out` before mutating the box; failures report the
   completed step; `--init none` still installs the `huitz` shim; auto-detect
   failure is a hard error, explicit `none` is allowed; Windows installer checks
   `$LASTEXITCODE`.
7. Re-arm removes per-user report mirrors; motd rejects control characters;
   spoiler lint sees through markup; docs flag drift fixed.

Exit: boxbuilder/packaging tests, including stale-state and reinstall-order
regressions, plus a full honor and ranked build against a disposable VM.

## Batch 8 — test-suite and documentation

1. Fix default-suite dependency docs (PyYAML, requests, python-dotenv) and make
   the Proxmox tier skip with a reason instead of exiting 5.
2. Remove hard-coded test counts; mark the Fedora partial check honestly; stop
   claiming "all check types" when five are not live-tested.
3. Convert fixed-sleep integration tests to state polling where practical.
4. Add behavioral tests for `sync-report.sh`, rearm, queue/directive edge cases,
   build CLI flags, and the Windows installer where mockable.
5. Update architecture.md, README, CLI.md, TESTING_GUIDE.md, tests/README.md,
   packaging/README.md, boxbuilder/README.md, AGENTS.md, and add release notes.

Exit: docs match code; `pytest` passes; no stale counts/claims.

## Batch 9 — release verification

- `pytest` full default tier.
- `python3 packaging/build_zipapp.py`; run the zipapp under a clean interpreter.
- Honor E2E: compile → install → answer → grade → snapshot/CLI/HTML.
- Ranked loopback E2E: enroll → check-in → score → directives → restart/resync.
- Proxmox: two-machine ranked run and the all-check-types tier where credentials
  are available (using the proxmox-ops skill); otherwise record exact blockers.
- Windows: clone/install/grade if a Windows template is available.
- Reinstall honor→ranked on a disposable clone and confirm no rubric/identity
  survives.
- Bump `AGENT_VERSION` to `1.0.0`, write `RELEASE_NOTES_1.0.md`, final review of
  the diff and commit history.

---

## Verification log (2026-10-20)

Automated:

- `pytest` default tier: **1003 passed, 1 skipped (root-only), 5 deselected**
  in 252s.
- `pytest tests/unit`: 892 passed, 1 skipped.
- `pytest tests/integration -m "not proxmox"`: 105 passed.
- All 13 box scenarios compile through the hardened authoring validator
  (including the untracked Saltmarsh Exchange work).
- `packaging/build_zipapp.py` builds and the `.pyz` runs `huitz help`.
- `pyflakes` has only string-annotation false positives remaining.

Real infrastructure (Proxmox, fresh linked clones):

- `test_ranked_two_machines.py`: **1 passed** (engine VM + agent VM, real
  network hop, enrollment → check-in → leaderboard total=10).
- `test_local_honor_distribution.py`: **Ubuntu passed, Fedora passed**.
- `test_all_check_types_live.py`: **Ubuntu 70/70 and Fedora 70/70 passed**
  (Fedora over root SSH; the guest agent's SELinux domain was the old 30/70
  limit, not the product).
- `test_windows_live.py`: **Windows Server 2022 90/90 passed** across
  `file_regex`, `permission`, `user_group`, `service_state`, `process_state`,
  `registry_value`, `powershell_json`, `http_uptime`, and `db_query`; the
  opt-in install test passed on a prepared clone (files, `icacls` seal, SYSTEM
  `HuitzilopochtliAgent` task, 80/80 first report).
- Full fast suite: **1005 passed, 1 skipped, 7 deselected**.
- Compiled `chocolate-factory` honor artifacts on a fresh clone: agent graded
  (`Total: 100` baseline with no vulns planted), `huitz score` rendered the
  board and exited 0, `huitz forensics` displayed and edited the answers file,
  and `huitz grade` re-ran successfully.
- **Real boxbuilder SSH install**: after regenerating the clone's machine-id
  (template 106 hands every clone the same DHCP identity; the earlier timeout
  was an IP collision, not a bridge issue), `boxbuilder install --init systemd`
  placed the file set, sealed `/opt/.huitzilopochtli` 0700, installed the timer
  and `huitz` shim, and the non-root player CLI read the mirrored report.
- **Real honor→ranked reinstall** on that same box, against a live engine on a
  second VM: the install removed `.score.dat`, installed the ranked config and
  identity, disabled/removed the honor timer, enrolled, and produced
  `total=10` on the engine leaderboard. The player CLI showed the ranked score.
  Both test VMs were destroyed afterward.
