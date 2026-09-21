# Project sweep: bug fixes + test/doc hygiene

## Context

The user asked for a full-project review of `huitzilopochtli` (a security-hardening
scoring engine) to find and fix bugs and improvements. Three parallel audits plus a
direct read of the core scoring/compile/validation code surfaced ~50 issues. Baseline
is green: **616 unit + 56 integration tests pass** on Python 3.14.

The user chose **Tier 2 scope**: fix confirmed high-impact bugs (scoring loss, crashes,
Windows breakage, local-root security) **plus** test/doc hygiene (dead/tautological
tests, missing coverage, stale docs) — but **not** the ranked-mode protocol/architecture
changes (those are listed under "Deferred" and left untouched). Delivery: apply fixes,
add tests where noted, run the full suite, stage as **one commit** (no push).

## Verification pass (done before this plan was finalized)

Every finding below was re-checked against the actual code; the audit reports proved
accurate and **no false positives** were found. Highlights confirmed empirically:

- **dpkg** (`agent/platform/pkg.py:16-23`): returns installed on rc==0 without reading
  `Status:` — a removed-not-purged package scores as installed. Real.
- **mdhtml** (`boxbuilder/mdhtml.py`): rendered the real `boxes/opochtli-landing/assets/README.md`
  and a generated opochtli answer key. The README emits a collapsed blockquote with 7
  literal `&gt;` and a `**MariaDB…3306**` bold split across `<li>`/`<p>`; the answer key
  shows literal `*Goal:*` on all 9 checks. Real and player-visible.
- **engine crashes** (`engine/server.py:185,300-309,334-339`): `hmac.compare_digest` on two
  `str`s, unguarded `scenario_name`/`inf` ttl, and non-dict `adversary` all escape the
  handler's try blocks → connection drop. Real.
- **empty `allowed: []`** (`boxes/pinecrest-hospital`): answer key renders `must be limited
  to ` with nothing after. Real.
- **dead code** confirmed by grep: `get_token`/`save_sla_state`/`get_sla_state` have zero
  callers; `create_box`/`consume_token` survive only in a stale docstring; duplicated
  `_agent_version_compatible` at `checkin.py:35` and `:46`.
- **test no-assert** (`test_boxbuilder_mdhtml.py:15-16`): a string literal + a bare `in`
  expression, so link rendering is untested. Real.

**Severity refinements** (still real, but scoped honestly as latent, not actively firing):
- Items 3 (collector deadline), 6/7 (Windows registry/service), 32 (ssh deadlock), 33
  (engine URL path) are **latent** — they need a specific trigger (>20 near-timeout checks;
  a WOW6432Node-only value or forged signed manifest; a >2 MB command; a path-prefixed
  `engine_url`) that no current scenario hits. Worth fixing defensively; not urgent.
- The three local-root security items (10, 11, 12) are **defense-in-depth**: on these boxes
  the players are the admins, so the pre-planted-symlink attacker is a planted low-priv
  account, and `fs.protected_symlinks` mitigates on a default kernel. Real hardening, not a
  high-severity remote hole.

Other claims verified by direct read: `dpkg`, `hmac.compare_digest`, the ssh.py stdout
`print`, the opochtli `box.yaml` DB contradiction, the pinecrest misleading `display`, the
`bind_shell` bare `is-enabled`, and the authoring-validation gaps (`sla`/type/duplicate-id/
empty-matcher).

---

## Fixes by area

### A. Agent — scoring correctness & Windows (highest player impact)

1. **`agent/platform/pkg.py:14-23`** — `_dpkg_check` returns installed on rc==0 without
   checking `Status:`. A removed-but-not-purged package (`deinstall ok config-files`,
   exits 0) scores as still installed, denying points for a correct removal. Fix: require
   `Status:` to contain `install ok installed`. Add a rc==0/config-files case to
   `tests/unit/test_platform.py::TestPkgDpkg`.

2. **`os.rename` → `os.replace`** (Windows raises `FileExistsError` on existing dest;
   only `agent/transport.py:134` is correct today). The five **overwrite** sites are the
   real bug — `agent/snapshot.py:159` (report.json every grade, fires on the pinecrest
   Windows honor box), `agent/cli.py:515` (answers file, `huitz forensics`),
   `agent/notify.py:73` and `:170`, `agent/identity.py:148` (ranked seq bump). The two
   `agent/__main__.py:234` and `:418` sites are write-once-guarded (dest never pre-exists),
   so they are safe today; convert them too for consistency. Add a Windows-path test
   (overwrite an existing snapshot/answers file) in `tests/unit/test_windows_support.py`.

3. **`agent/collector.py:128-179`** — the global deadline is computed once at submit time,
   so checks still queued behind the 20-worker cap are marked TIMEOUT without running →
   scored "not satisfied". Fix: give each check a deadline measured from when its worker
   starts (stamp a start time in `_run_one`), or size the deadline as
   `max(timeout_s) * ceil(len(checks)/max_workers)`. Add a test: >20 checks each ~real-timeout,
   assert none are spuriously TIMEOUT.

4. **UTF-8 on text reads** — files are written UTF-8 but read with the locale encoding
   (cp1252 on Windows), corrupting non-ASCII forensics answers and scoring them wrong.
   Add `encoding="utf-8"` (keep `errors="replace"`) at: `agent/cli.py` `_read_answers`,
   `agent/checks/forensics.py:37`, `agent/checks/file_regex.py:32`,
   `agent/checks/user_group.py:18,32`.

5. **`agent/snapshot.py:48,140`** — Windows honor countdown fix reached the HTML report but
   not the snapshot (default `honor_interval_s=70`), so `huitz score/watch` show "overdue"
   for ~3 of every 5 min. Pass the resolved interval through `build_snapshot`; guard the
   `None`-on-POSIX case. Pin the snapshot value in `test_windows_support.py`.

6. **`agent/checks/registry_value.py:34-43`** — the "32-bit view fallback" never runs
   (`return` on first `FileNotFoundError`) and uses `KEY_READ`, not `KEY_WOW64_32KEY`.
   Fix: `continue` on `FileNotFoundError` for all but the last mask; make the fallback
   `KEY_READ | KEY_WOW64_32KEY`. Add a WOW6432Node test.

7. **`agent/checks`/`platform/windows.py:56-63`** — service name interpolated into a
   double-quoted PowerShell string (only quotes filtered; `$(...)`/backtick expand). Add a
   shared name allowlist regex (reuse the shape of `agent/adversary/actions.py:_SERVICE_NAME_RE`)
   and reject/validate before interpolation.

8. **`agent/reporter.py:81-85`** — `max_possible` (points) compared against `vulns_fixed`
   (a count); the "/ N max" suffix vanishes when they coincide. Compare against `b.total`
   or drop the guard.

9. **`agent/__main__.py:264-268`** — creates a user's `~/Desktop` as `root:root`. Only
   `makedirs` when missing *and* chown to the resolved desktop user, else fall back to
   `config_dir`.

### B. Agent — local-root security hardening (collector runs as root)

10. **`packaging/sync-report.sh:37,40`** — `cp` into an attacker-writable `~/Desktop`
    follows a pre-planted symlink → root overwrites arbitrary files every 60s. Fix:
    `install -m 0644 -o "$nakon_u" -g "$nakon_u"` or `cp --remove-destination`. Also
    `sync-report.sh:34-43`: `cp` under `set -e` aborts the whole sync on one user's
    failure — add `|| continue`.

11. **`agent/notify.py:161-174`** — root writes WAV to fixed `/tmp/huitz-<kind>.wav.tmp`
    (symlink/dir race). Extract into a root-owned dir (install dir or per-run
    `mkdtemp`). Update the path assertion in `tests/unit/test_agent_notify.py:128`.

12. **`agent/adversary/actions.py:30-37,120-127`** — sandbox uses `abspath` (not
    `realpath`) under world-writable `/tmp/...`; symlinked base escapes containment. Use
    `os.path.realpath` on both sides, create base `mode=0o700`, open with
    `O_CREAT|O_EXCL|O_NOFOLLOW`.

13. **`packaging/rearm.py:84-146`** — re-arm removes only `<report_dir>/report.json`, not
    the per-user `~/Desktop/report.json`/`report.html` mirrors that `sync-report.sh`
    populated, so `huitz score` shows the dead session's grade after reset. Enumerate the
    same home dirs and remove the Desktop mirrors. (Also: unused `install_dir` param.)

### C. Agent — robustness improvements (Tier 2)

14. **`agent/__main__.py` report write** — make the HTML report write atomic
    (`report_path + ".tmp"` + `os.replace`) like snapshot/notify/answers.
15. **`agent/transport.py:119-139`** — cap the queue file (drop oldest beyond N entries /
    M bytes; note the drop in the warning).
16. **Consolidate the "real interactive user" heuristic** — three copies
    (`__main__._primary_desktop_dir` uses `uid>=1000` only; `notify._real_users` and
    `cli._desktop_report_paths` use `1000<=uid<60000`). Extract one `agent/users.py`
    (`real_users()`, `primary_desktop_dir()`); make bounds consistent. Update the three
    call sites.

### D. Engine — HTTP handler crashes & validation (crash fixes, not protocol redesign)

17. **`engine/server.py:185`** — `hmac.compare_digest` on two `str`s raises `TypeError`
    on a non-ASCII admin-token header (latin-1 decoded), dropping the connection instead
    of 403. Compare bytes. Wrap `do_GET`/`do_POST` bodies in a catch-all that emits a
    JSON 500 (so no handler exception drops the socket).
18. **`engine/server.py:334-339`** — non-dict `adversary` → `AttributeError`. Add
    `isinstance(adversary, dict)` guard at the top of `_validate_adversary_pool`.
19. **`engine/server.py:300-309`** — type-check `scenario_name` (non-empty str) and
    require `math.isfinite(ttl_s) and ttl_s > 0`; pass `allow_nan=False` to `json.dumps`
    in `_send_json` (inf/NaN TTL currently yields invalid JSON and a never-expiring token).
20. **`engine/sla.py` / `common/schema.py:409-429`** — validate `hysteresis_fail_n` /
    `hysteresis_ok_n` as positive ints in `validate_rubric` (0 inverts the state machine).
21. **`engine/server.py:365-371`** — route the `HUITZILOPOCHTLI_ENGINE_RECORD_PATH`
    seeding path through `validate_rubric` + `_validate_adversary_pool` and exit non-zero
    on failure (parity with `POST /admin/scenarios`).
22. **`engine/store_schema.py`** — add
    `CREATE INDEX IF NOT EXISTS idx_scores_scenario ON scores(scenario_name, total DESC)`.

### E. Authoring — validation gaps (turn bare tracebacks into sourced errors)

Fix `authoring/validate.py` so malformed scenarios are rejected with `"{source_path}: ..."`
messages instead of crashing `compile`/collector/evaluator later:
23. Validate `expect.sla` shape (mapping; positive-int `interval_s`, `points_per_interval`)
    — currently a bare `KeyError` from `compile.py:122`.
24. Type-check `checks[]` fields: `id`/`display` non-empty str, `max_points` int,
    `timeout_s` number, `scenario.name` str, `scenario.version` int, `hosts` non-empty.
    Validate `check.type` against a literal registry tuple (pinned by a unit test, since
    the collector registry can't be imported from `authoring/`).
25. Detect duplicate `checks[].id` (mirror the existing forensics-id check).
26. Fix the "empty matcher" guard to check `set(expect) - {"points","sla"}` and name the
    offending `checks[N]` (current guard misses `expect: {points: 5}`; comment is misleading).

### F. boxbuilder — bugs

27. **`boxbuilder/mdhtml.py:49-127`** — the Markdown subset is too small for the Markdown
    the repo actually authors: no blockquotes, no single-`*` emphasis, no lazy list
    continuation. Shipped Desktop `README.html` (all five boxes) and every `--html`
    answer-key show literal `**`/`>` and broken lists. Add: lazy continuation (append a
    non-blank non-marker line to the current `<li>`), a `>` blockquote branch, single
    `*`/`_` emphasis after `_BOLD_RE`, and join paragraph/list-item text before `_inline`
    so bold spans wrapped lines. Add tests using the real `boxes/*/assets/README.md` as
    fixtures.
28. **`boxbuilder/answerkey.py`** — emit markup mdhtml supports once #27 lands
    (`**Goal:**`, blank-line separators not trailing-double-space breaks) so handouts
    render.
29. **`boxbuilder/answerkey.py:102-106`** — empty `allowed: []` (pinecrest RDP check)
    renders a dangling "…limited to". Return "must have no members" when empty.
30. **`boxbuilder/answerkey.py:134-166`** — add `registry_value` and
    `powershell_json`/`command_json` branches to `goal_line`/`scored_on` (18 of 33
    pinecrest checks currently render content-free).
31. **`boxbuilder/providers/ssh.py:295`** — `print(...)` to stdout violates the one-JSON-
    line contract. Add `file=sys.stderr`. Assert `capsys.out == ""` for the non-JSON
    install path.
32. **`boxbuilder/providers/ssh.py:191-222`** — drain stdout/stderr before/while awaiting
    `recv_exit_status()` (paramiko 2 MB window deadlock on verbose commands); lower the
    default 1800s timeout for short commands.
33. **`boxbuilder/engine.py:27-33,104,118`** — `_split_url` discards the URL path prefix,
    so a `engine_url` with `/api` POSTs to the wrong path (404). Keep
    `parts.path.rstrip("/")` and prefix it (or reject a non-empty path clearly).
34. **`boxbuilder/spec.py:70-86,112-113`** — guard value *types* (`scenario.scenario` must
    be a dict; required keys in `box.yaml` must be str) so `compile --json` gives the
    promised clear error, not a raw `AttributeError`/`TypeError`.
35. **`boxbuilder/cli.py:104-120` + `spec.py:135`** — resolve
    `HUITZILOPOCHTLI_PROVIDER_PASSWORD` (env/prompt) on the `--spec` path too, not only
    direct-flag. Document it in `boxbuilder/README.md`.
36. **`boxbuilder/pipeline.py:358-363`** — check `rm_cmd.ok` for the stale-baseline wipe
    and log a warning on failure (silent today; the file it removes is often root-owned).
37. **`boxbuilder/artifacts.py` / `authoring/compile.py:260-263`** — write `rubric.json`,
    `.score.dat`, `engine_record.json`, and `artifacts/answer-keys/*` with `0o600` (the
    plaintext answer key is currently `0644`, unlike `authoring.key`). Reuse the
    `os.open(..., 0o600)` pattern from `keys.py`; or `chmod 0700` the artifacts dir.
38. **`boxbuilder/cli.py:292,316` + `providers/base.py:70`** — add `"windows"` to both
    `--init` choice tuples and the base docstring (currently unreachable when Windows
    auto-detect fails open to `"none"`).
39. **`boxbuilder/providers/__init__.py:11-19` + `base.py:118-125`** — narrow the
    import-swallowing `except` to `ImportError` and log it (a real `SyntaxError` in
    ssh.py currently yields a misleading `available: []`); use or drop the unused `cfg`.
40. **`boxbuilder/answerkey.py:307-311`** — resolve the default output dir against the
    repo root (not CWD) so the handout isn't scattered per-invocation; or document the CWD
    behavior. Add a test on the default path.

### G. boxes / authoring content

41. **`boxes/opochtli-landing/box.yaml:7`** — delete the "backed by local MariaDB on
    127.0.0.1:3306" clause; it contradicts lines 20-30 (shared remote DB) and would send a
    template-prepper down the wrong path.
42. **`boxes/pinecrest-hospital/scenario.yaml:126`** — change `display` from "…is removed"
    to "…is disabled" / "can no longer log in" (deleting the account destroys the paired
    forensics evidence; the solution text and sibling checks say disable).
43. **`boxes/opochtli-landing/scenario.yaml:421`** — `bind_shell_removed` uses bare
    `is-enabled >/dev/null` (exits 0 for `static`/`indirect`); use `| grep -q '^enabled$'`
    like the sibling `cockpit_removed` (its comment calls the bare form out as wrong).
44. **`boxes/shared/fix-xubuntu-vnc-display.sh:154-156`** — drop the pointless
    `mkdir -p /run/user/$uid` + chown (or `chmod 700`); it creates `XDG_RUNTIME_DIR`
    world-accessible and is never used without the socket.

### H. Repo hygiene

45. **`DISASTROUS_PHARMACIST`** (20 MB untracked ELF at repo root, referenced by nothing,
    name doesn't even match the `DISASTEROUS_PHARMACY` codename, and the real beacon is
    base64-embedded in `realm-beacon.json`). Add a `.gitignore` entry (and note it as a
    stray build artifact); do **not** delete the file itself without asking.

### I. Tests & docs hygiene

46. **Dead/tautological tests**: `tests/unit/test_boxbuilder_mdhtml.py:15-16` (no real
    assert — link rendering untested); `test_boxbuilder_opochtli_landing.py:90` (asserts a
    field that never exists — assert on real answer strings instead);
    `test_store.py:124-137` (tie-break never reaches `box_id`, clock-flaky — pass explicit
    `updated_at`); `test_adversary_oracle.py:142-148` (dead var + conditional assert).
47. **Missing coverage**: `enroll_box_atomic` status branches (incl. `expired`,
    `scenario_mismatch`, `duplicate_box`/409); the `410 token expired` enroll path
    (architecture.md §19); `pipeline._verify_state_fingerprint` (0 tests today — the guard
    against scoring the wrong box); the three uncovered opochtli firewall scripts
    (`default_deny_all`, `cockpit_removed`, `bind_shell_removed`) with stubbed
    `iptables`/`ss`/`systemctl`/`python3` on PATH.
48. **Neutralize network in unit tier**:
    `test_boxbuilder_opochtli_landing.py:124-144` makes real outbound connections
    (`default_deny_all` probes 192.168.100.10:3306 / 127.0.0.1:80). Stub the probes or move
    to integration; fix its docstring ("iptables-save" → "iptables -S").
49. **Delete dead code**: superseded `engine/store.py` methods (`get_token`,
    `consume_token`, `create_box`, `save_sla_state`, `get_sla_state`) + port their tests
    onto the atomic path; duplicated `_agent_version_compatible` / version-check block in
    `engine/checkin.py:46-117`; unused `boxbuilder/pipeline.py:14` import (and its now-false
    comment) + inline `_load_state` duplication; dead `_real_spec` in
    `tests/integration/boxbuilder/test_package_and_build.py`.
50. **Reconcile `tests/integration/test_ranked_loopback.py`**: the seq-desync regression
    test its docstring claims to run is commented out. Re-enable it, or delete it and fix
    the docstring so coverage claims match reality.
51. **Doc drift**: `boxbuilder/cli.py:8-13` usage block (nonexistent `--artifacts`, wrong
    `package --out`); `tests/README.md` (stale "278 passed", 7-check-type list now 11, no
    boxbuilder tier, contradictory integration timings); `boxbuilder/README.md:406-408`
    (all five boxes now backfilled, not two) and `:436-437` + `test_boxbuilder_theme.py:4-6`
    (vulndb is a fake CLI subprocess, not a fake `http.server`); `engine/enrollment.py`
    docstring (removed `create_box`/`consume_token` flow); `providers/base.py` +
    `vulndb.py:229` docstrings.

---

## Deferred (Tier 3 — NOT in this change, flagged for the user)

These are real but touch ranked-mode protocol / signed-manifest / architecture.md
invariants and live-deployed behavior; left untouched per the chosen scope. Two are
data-integrity issues worth prioritizing next:

- **engine#6** `engine/checkin.py:143-200` — seq is consumed before scoring and there is
  no enclosing transaction; a crash mid-checkin can lose a check-in permanently or leave
  SLA rows partially advanced. (Data integrity.)
- **agent#8** `agent/transport.py:235-255` — a permanent rejection of an old *queued*
  bundle silently discards the freshly collected one and desyncs `last_seq`. (Data loss.)
- **engine#4** scenario_version reconciliation + `409 scenario_version_mismatch` (v1 box
  silently scored against a v2 rubric — contradicts §14.3).
- **engine#5** `next_checkin_s` returns the SLA accrual granularity, not the poll cadence
  (`sla.interval_s: 1` makes boxes spin).
- **engine#8** the §12.1 "engine-caused outage floor" for adversary directives is
  unimplemented (adversary penalties never applied to any score).
- **agent#7** enrollment has no timeout and no `URLError`/`OSError` handling (first ranked
  boot can hang forever or die).
- **agent#11** `engine_url` is not required to be `https`; directives from an
  unauthenticated `http://` response are executed.
- **packaging#18** `test_zipapp.py` cannot detect a third-party import in `agent/`
  (subprocess inherits `site-packages`) — run the `.pyz` with `-I` + empty `PYTHONPATH`,
  or walk archive imports with `ast`. (Could fold into I if cheap.)

---

## Verification

1. **Full suite**: `python3 -m pytest tests/unit tests/integration -q` (unit ~60s,
   integration ~100s). All must stay green; new tests (items 1-6, 46-48) must pass.
2. **mdhtml (#27)**: render each `boxes/*/assets/README.md` through `markdown_to_html`
   and assert no literal `**`/`>`/`*` leak; render an opochtli answer-key with `--html`
   and eyeball a check block.
3. **answer-key end-to-end (#28-30,40)**:
   `python3 -m boxbuilder answer-key --scenario boxes/pinecrest-hospital/scenario.yaml --html --json`
   → valid single JSON line, no dangling "limited to", registry/powershell goals present.
4. **JSON contract (#31)**:
   `python3 -m boxbuilder install ... --json | jq .` still parses with a non-writable shim.
5. **Windows paths (#2,#5,#6)**: rely on `test_windows_support.py` additions (no real
   Windows host available).
6. **Import boundaries** (AGENTS.md invariant): after the `agent/users.py` extraction (#16),
   confirm `agent/` + `common/` remain stdlib-only (grep imports) and the zipapp still
   builds (`python3 -m packaging.build_zipapp` + `test_zipapp.py`).
7. **Leak guard**: `test_boxbuilder_answerkey.py::test_solution_never_reaches_manifest_or_rubric`
   must still pass (no `solution:`/answer material in manifest/rubric).

Then stage everything as **one commit** (message summarizing the areas touched; no push),
ending with the required `Co-Authored-By` trailer.
