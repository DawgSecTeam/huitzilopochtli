# Huitzilopochtli 1.0.0

Release branch: `release/1.0-hardening`

This release closes the full-project review findings and makes the ranked
protocol, score ledger, and box factory safe to run as a 1.0 system.

## Score integrity

- The SLA `max_intervals_per_checkin` cap now **forfeits** a long outage's
  backlog instead of paying it out over later check-ins. DISABLED/normal
  fractional carry-over is unchanged.
- `prohibited` results now report `passed` as "requirement satisfied", so a
  detected forbidden state is no longer shown as "Passed: yes".
- Zero-point non-SLA checks are rejected at author time; a passed check can no
  longer leave progress permanently below 100%.
- Rubric matchers are argument-validated at upload/compile time, and the
  evaluator contains a bad entry instead of aborting every check-in.
- Scenario records are keyed by `(scenario_name, scenario_version)`. Uploading
  a v2 rubric no longer silently rescores v1-enrolled boxes.
- Adversary events have stable explicit ids; issue-time `fire_time` is
  persisted and an optional `affects_check` mapping forces the named SLA DOWN
  from issuance until a later check-in reports restoration.

## Crypto

- Ed25519 verification rejects small-order and non-canonical public keys/R
  points, restoring the enrollment proof-of-possession contract.
- The reference recursive modular exponentiation was replaced by the
  equivalent built-in `pow()`, making the test suite and check-ins several
  times faster.
- Canonical signing payloads reject NaN/Infinity and keys that collide after
  NFC normalization instead of silently merging them.

## Engine / protocol

- `/enroll` rejects non-object bodies and out-of-range versions cleanly.
- Check-in loads the rubric only after signature verification, selects the
  enrolled version, and caches parsed records.
- Per-source rate limiting on `/enroll` and `/checkin` (configurable).
- Engine DB and SQLite artifacts are created `0600`.
- Leaderboard ties use an immutable first-scored timestamp.
- In-place schema migration upgrades pre-1.0 databases.

## Agent

- Per-check timeouts are measured from when each check starts; queued checks
  are no longer starved by one global deadline.
- The transport queue is bounded, fsync'd, and dead-letters a bundle that keeps
  getting 5xx instead of blocking all later evidence. Oversized bundles are
  shrunk client-side before the engine's 1 MiB cap.
- Directive dedup fails closed on a wrong-shaped record; re-arm removes the
  `.directives` file.
- Identity files are tightened to `0600`, fsync'd, and survive corrupt-file
  diagnosis; 409 token-consumed vs box-conflict are distinguished.
- Config booleans are strict, manifest/config modes must match, and permanent
  enrollment/TLS failures fail fast instead of retrying forever.
- The ranked dashboard survives agent restarts; countdowns are anchored to box
  receipt time; Windows honors the same 300s interval in HTML and snapshot.
- Honor grades take a lock, write reports atomically, and only advance the
  notification baseline after publication.

## Windows / CLI

- Fixed Windows `huitz forensics` (`os.chown`), UTF-8/BOM handling across
  answers/PowerShell/collectors, and Windows `kill_service`/`flush_firewall`.
- Terminal output is sanitized against control/escape injection; accents are
  strictly validated; corrupt snapshots produce clean errors; `--report` /
  `$HUITZ_REPORT` are authoritative; broken pipes exit 141; per-question
  answers paths and full-file edits work.

## Boxbuilder / packaging

- Compile-state fingerprints refuse stale plant/install runs.
- Reinstalls clear the install directory unconditionally (root POSIX and
  Windows), so an honor→ranked rebuild cannot leave the answer key, identity,
  or `.enrolled` behind.
- Artifacts are `0700`; rubrics/engine records/configs/answer keys are `0600`;
  the deploy config (SSH password) is temporary and deleted; enrollment tokens
  are not left in JSON build output.
- Admin API refuses plain HTTP to non-loopback engines unless explicitly
  overridden; SSH requires pinned host keys by default; large command output
  is drained concurrently; `--image-out` is validated before mutating a box;
  `--init none` still installs the `huitz` shim; Windows installer checks exit
  codes.
- Re-arm clears per-user report mirrors and transport/directive state.

## Tests / docs

- Added regressions for every finding above (SLA drain, matcher crashes,
  small-order keys, version isolation, docking, queue limits, Windows CLI,
  boxbuilder state/cleanup, rearm, etc.).
- Removed hard-coded test counts, stale “blocked” claims, and “all seven check
  types” claims; added `requirements-dev.txt`; Proxmox tier skips with a
  reason and Fedora is an honest strict xfail.
