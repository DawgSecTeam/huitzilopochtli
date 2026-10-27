# Ranked-mode test matrix

What covers the ranked surface, how to run each tier, and what is still open.
This is a coverage map, not a changelog: for counts, run
`pytest --collect-only -q`. Hands-on local runs are in `TESTING_GUIDE.md`; tier
mechanics (fixtures, env) are in `tests/README.md`.

## Tiers

| Tier | Command | Needs | Runtime |
|---|---|---|---|
| Unit | `pytest tests/unit` | nothing beyond `requirements-dev.txt` | seconds |
| Integration | `pytest tests/integration` | loopback sockets only | a few minutes |
| Default | `pytest` | as above (Proxmox deselected) | a few minutes |
| Proxmox | `pytest -m proxmox` | `tests/proxmox/.env` + a reachable Proxmox host | tens of minutes |

`pytest.ini` deselects the `proxmox` marker by default; the Proxmox conftest
auto-skips that tier (with a reason) when its `.env` is absent. Single suites:

```bash
pytest tests/integration/test_ranked_loopback.py -q
pytest tests/integration -q -k "competition or claims"
pytest tests/unit/test_authoring_validate.py -q
```

**Runtime is crypto, not a hang.** Every check-in costs a client-side Ed25519
sign and a server-side verify of the vendored pure-Python reference
implementation. On an idle machine a sign/verify is well under a second, but a
suite that runs dozens of round-trips legitimately takes a couple of minutes,
and a loaded host makes each one slower. `tests/integration/test_ranked_loopback.py`
alone is ~70s for three tests, and the whole default suite can take several
minutes on a busy host. Do not "fix" a slow ranked suite by shortening
timeouts; check whether it is simply signing. One unit test (`test_forensics_template_as_root…`)
skips unless the suite runs as root.

## Coverage matrix

| Area | Suites | What is pinned |
|---|---|---|
| Scenario model / build targets | `test_scenario_modes.py`, `test_authoring_validate.py`, `test_boxbuilder_spec.py` | One `scenario.yaml`, two targets; an honor build never sees `ranked:` content; `mode` defaults and `--mode` overrides; `engine_url` resolution order; `${VAR}` pool expansion and its unset-variable error; pool validation (honor rejection, required keys, bad values); `box.yaml` carries no host/password/mode |
| Handbook spoiler lint | `test_authoring_readme_lint.py` | Forensics answers in `theme.readme` block the compile; solution copy-paste, mutation commands, and planted paths warn; every in-repo box is lint-clean |
| Services and SLA authoring | `test_services_compile.py`, `test_tcp_port_check.py` | `svc_` ids and rubric SLA entries, service-id collisions, `http_uptime`/`tcp_port` evidence |
| Enrollment and identity | `test_ranked_loopback.py`, `test_ranked_protocol_errors.py` | First-boot enroll, restart without re-enroll, token single-use/expiry/scenario mismatch, duplicate box, bad signature, Box-header tripwire |
| Check-in, seq, and queue | `test_ranked_loopback.py`, `test_ranked_protocol_errors.py`, `test_transport_and_collector.py` | Monotonic seq, replay → 409 with `last_seq`, hard-kill-mid-check-in recovery, offline queue flush in order, dead-lettering |
| Wire hardening | `test_ranked_protocol_errors.py`, `test_review_hardening.py` | Check order (box → schema → signature → scenario → seq); typed/range-bounded/nesting-capped bundles; answer-key redaction on raw bodies; disabled admin surface |
| Scoring and rubric | `test_evaluator.py`, `test_sla.py`, `test_rubric_codec.py`, `test_store.py`, `test_canon.py`, `test_schema.py` | Point-in-time evaluation, category sums, outage-cap drain, per-version rubrics, deterministic tie-breaks, receipt clock |
| Adversary | `test_adversary_actions.py`, `test_adversary_oracle.py`, `test_ranked_adversary.py` | Closed action vocabulary, per-event deterministic seeding, in-window fire, at-most-once across resends/restarts, SLA outage floor |
| Engine resilience | `test_ranked_resilience.py`, `test_ranked_loopback.py` | Scores/seq/T0 survive restart; verify-gate 503 backpressure and retry convergence; token-enroll race has exactly one winner |
| Competition domain | `test_competition.py` | Join/run clock/max players/expiry, one live slot per player, leave forfeit, ended-only delete, active-name block, service rows, shared rank for equal totals |
| Claims and pools | `test_claims.py` | Per-competition `ensure_pool` (provision/reuse/template mismatch/409/missing block), prebind-disabled fallback, ticket polling, backoff, code rotation, cleanup own vs legacy pool, pre-provisioned clone teardown, codes never exposed |
| Competition HTTP/UI | `test_competition_http.py`, `test_competition_admin_ui.py`, `test_web_pages.py`, `test_admin_scenarios.py` | Public join → signed `/join` → check-in → leaderboard → admin End over real HTTP; Basic login + CSRF; page polling/theme/gating; boxes-only scenario picker (engine parses boxes/*/scenario.yaml; versions never rendered, non-current refused) |
| Reports and CLI | `test_reporter.py`, `test_huitz_cli.py`, `test_join_start.py` | Hardening/service split, event clock + position, 10-tick service strip, `huitz join` starts the unit on POSIX and Windows |
| Packaging | `test_zipapp.py` | The built `.pyz` ranked against a local engine; source-tree/zipapp equivalence |
| Boxbuilder | `tests/integration/boxbuilder/`, `tests/unit/test_boxbuilder_*.py` | compile/plant/install/package, competition mode (no token, agent unit left stopped), mode flags, no deployment facts in specs, engine client |
| Live VMs | `tests/proxmox/*` | Honor distribution, every check type on Ubuntu/Fedora, Windows checks + install, ranked across two real machines — see `tests/README.md` |

## Harness facts that change how you debug

- **Real processes, real sockets.** Integration tests start
  `python3 -m engine.server` and `python3 -m agent` subprocesses on
  `127.0.0.1` with real sqlite files and real signing; nothing is mocked.
  Engine fixtures are module-scoped, and seqs come from one monotonic counter
  because the engine rejects `seq <= last_seq` even for a request designed to
  fail later.
- **Boxbuilder integration uses fake providers.** `tests/integration/boxbuilder/`
  drives the pipeline against an in-process fake handle, so it needs no VM and
  no network; live SSH behaviour is only covered by the Proxmox tier.
- **Proxmox clones need a fresh machine-id.** Ubuntu templates have shipped
  with a duplicated `/etc/machine-id`, so two clones DHCP-collide; the helper
  regenerates it per clone. Two-machine ranked runs also need
  `HUITZILOPOCHTLI_BIND=0.0.0.0` on the engine VM.
- **Guest-agent vs SSH.** Most Proxmox tests push files with the QEMU guest
  agent; Fedora's agent is SELinux-confined (no outbound `connect()`, no
  `/opt` writes) and Windows needs a real Python, so those paths use SSH.
  Guest-agent `file-write` caps a payload at 60 KB and has no append, so large
  pushes are chunked.
- **Nothing is committed with a count.** Coverage is defined by collected
  tests, not by a number in a doc; `pytest --collect-only -q` is the source of
  truth.

## Known defects and open decisions

These are current, not historical. Each was checked against the code while the
matrix was written.

1. **Scored services are self-reported.** A root player can forge
   `http_uptime`/`tcp_port` evidence. The competition UI says so, and the
   ceiling is documented in `RANKED_COMPETITION.md` §5; engine-side probing is
   a product decision, not a bug fix.
2. **Idle connections hold `MAX_CONNS` slots for 30s.** `Handler.timeout` is
   hardcoded, not env-tunable. Bounded under the friendly-leaderboard threat
   model; worth a knob if ranked is ever exposed to hostile networks.
3. **Chunked request bodies read as empty** and become a generic 400. Not
   smuggle-able (HTTP/1.0-style, connection closed per response) and the agent
   never sends chunked bodies, but the error is unhelpful.
4. **A root player can burn their own seq space.** Wire ints are bounded to
   `0..2^63-1`; jumping to the top makes every later check-in a 400.
   Self-inflicted only — it cannot touch another box.
5. **The player cookie is an unsigned bearer of the player id.** It is
   HttpOnly, SameSite, and random, but not signed; a leaked cookie can read
   `/c/<slug>/me` (not the admin console). Add an HMAC if the engine ever goes
   multi-tenant.
6. **No score-preserving box replacement.** Reissue, disqualify, and removal
   exist; replacing a bound box does not migrate its score or SLA state.
7. **Mid-run standings are not comparable.** Clocks start per player, so the
   board is a live status view; final standings are meaningful only at End.
8. **Agent TLS uses the system trust store.** The engine can serve TLS
   (`$HUITZILOPOCHTLI_TLS_CERT`/`$HUITZILOPOCHTLI_TLS_KEY`), but the agent calls
   `ssl.create_default_context()`, so a self-signed engine cert fails
   verification. A CA or pinning decision is still open, and no deployment doc
   commits to one.
9. **Admin pages are not rate-limited.** Only `/enroll`, `/join`, `/checkin`,
   and the public claim endpoint are. Fine on a trusted LAN.
10. **`scores` is keyed by `box_id` alone**, so one scenario per box. A box
    that needs two rubrics needs a schema change.
11. **No long-duration or scale soak.** Live runs have covered small fields for
    minutes to a couple of hours; nothing pins dozens of boxes for hours.

## Backlog for the next ranked round

1. **Type-aware authoring validation.** A per-check-type evidence schema
   (`file_regex` → `{matched: str}`, `http_uptime` → `{status: int}`,
   `permission` → `{exists: bool}`…) would catch the YAML boolean trap and an
   `expect` field that never matches at author time instead of at scoring time.
2. **TLS trust story.** Pick CA vs pinning, document it, and make the agent
   honour it; add a deploy recipe to `engine/deploy/README.md`.
3. **Scale/soak.** N boxes for hours with realistic cadences; measure the
   verify gate (`$HUITZILOPOCHTLI_MAX_VERIFY`) and decide whether check-in
   schedules need jitter.
4. **Service independence.** Either add optional engine-side probes or state
   plainly that uptime is box-observed only; today both are true.
5. **Score-preserving replacement**, if competitions ever allow swapping a
   dead box without losing its run.
6. **Admin rate limiting**, alongside the existing public-endpoint limiter.
7. **Multi-scenario boxes**, if a template ever needs more than one rubric at a
   time.
