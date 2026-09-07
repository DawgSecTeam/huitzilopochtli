# AGENTS.md

Guidance for agents (LLM or otherwise) working in this repo.

## What this repo is

**huitzilopochtli** is a security-hardening **scoring engine**. Teams *harden*
target systems; the engine collects evidence and produces a scored report. It
scores **correct hardening** — it does *not* deploy vulnerabilities. Two modes:
**honor** (offline, box scores itself) and **ranked** (a central engine
aggregates signed check-ins; rubric stays off-box). See `architecture.md` (the
source of truth) and `README.md`.

The thing that *deploys* vulnerabilities is **nakon**; the vulnerability catalog is
**vulndb-ui** (edited via the **vulndb-cli** client). Both are vendored as **git submodules**
under `vendor/` (`vendor/nakon`, `vendor/vulndb-cli`, pinned to a release). huitzilopochtli's
**boxbuilder** pairs with nakon to create practice boxes, and uses vulndb-cli — not raw HTTP —
to ensure its theme configurations + attachments exist in the catalog. Set them up with
`git submodule update --init --recursive` after clone.

Submodule init only brings tracked files, though — `vendor/nakon/.env` (vulndb DB creds +
`VULNDB_UI_URL`, same shape as `vendor/nakon/.env.example`) is gitignored and must be created
by hand on every machine that runs boxbuilder (boxbuilder runs nakon with `cwd=vendor/nakon`
specifically so it can read this file). `vendor/vulndb-cli` needs no on-disk config, but does
need `VULNDB_UI_URL` exported as a real environment variable (or passed via `--url`) in the
shell running boxbuilder — it otherwise silently falls back to `http://127.0.0.1:3000`.

## Invariants (do not break)

- **Collect/evaluate split.** Checks emit `Evidence` (structured `raw` facts + a
  human `reason`), never verdicts — scoring is a pure function of
  `(evidence, rubric, clock)` (`architecture.md` §2.1, §10).
- **The box never holds the answer key in ranked mode.** `collect_params` and the
  manifest carry what to collect, never expected values (§2.4, §6.1); the rubric
  stays engine-side (§3).
- **The box clock is diagnostic-only.** All timed scoring uses the engine's
  receipt clock; never score from box-claimed time (§2.3, §11.3).
- **The adversary is a closed allowlist with no network egress.** No scenario
  can author a callback, structurally — there is no code path for one (§2.7, §12).

## Building a practice box (the boxbuilder workflow)

`boxbuilder/` automates the four-step workflow: **(1) author** huitz checks +
nakon vuln selection → **(2) plant** vulns via nakon → **(3) install** the
huitz agent + manifest on the box → **(4) package** the box image.

You author **both** halves: the nakon config (which vulns to plant) and the
huitz scenario (which checks verify the hardening). boxbuilder does **not** know
the vuln→check mapping — you must ensure each planted vuln has a check that
awards points for the opposite (hardened) state.

```bash
# Browse + validate vulns (read-only, agent-safe):
nakon catalog list --json
nakon catalog show ssh-root-login --json      # read exactly what it plants
nakon catalog check --select nginx,ssh-root-login --json

# Author the two files (see boxbuilder/examples/ for a worked pairing), then:
python3 -m boxbuilder build --spec box.yaml --image-out box.ova --json
```

Each step is also runnable alone (`compile`/`plant`/`install`/`package`) so you
can verify between steps. See `boxbuilder/README.md`.

## Deploying a built box

`boxbuilder` plants + installs over ssh; promoting a build to a reusable
template is a separate manual loop, logged once in full at
`boxbuilder/REDEPLOY.md` (clone → snapshot → deploy → verify → seal).
Clone + snapshot before deploying, wipe `/etc/machine-id` before sealing, and
keep the previous template until the new one is confirmed in the field.

## Working in this repo

- **Python 3.10+** (built/tested on 3.14). No `pyproject.toml`/`requirements.txt`
  — install what you need by hand: `pip install pyyaml paramiko proxmoxer`
  (paramiko only for the ssh provider, proxmoxer only for the Proxmox test
  tier — see the boundary bullet below).
- **Dependency boundaries (hard).** `agent/` + `common/` are stdlib-only
  (vendored Ed25519 is the sole exception); `engine/` adds only stdlib
  `sqlite3`. PyYAML lives in `authoring/` + `boxbuilder/` only
  (`paramiko` for the ssh provider, `proxmoxer` in `tests/` only). The zipapp
  bundles `agent/` + `common/` and nothing else — a third-party import there
  silently ships breakage to every box.
- **No src-layout.** conftest.py puts the repo root on `sys.path`, so
  `import agent`, `import common`, `import boxbuilder` work everywhere.
- **Layout:** `common/` (shared schema + evaluator + crypto), `agent/` (on-box
  collector, ships as `.pyz`), `engine/` (ranked-mode server), `authoring/`
  (scenario compile + sign), `packaging/` (zipapp build + init units + re-arm),
  `boxbuilder/` (the practice-box factory).
- **Tests:** `pytest` runs unit + integration (Proxmox tier is deselected by
  default; opt in with `pytest -m proxmox` — its `.env` value is sourced
  from `workshop-vm-distribution`, not this repo). The ranked-loopback tier takes
  ~90s — that's the vendored Ed25519 (~seconds per sign/verify), not a hang.
  boxbuilder tests: `tests/unit/test_boxbuilder_*.py` and
  `tests/integration/boxbuilder/`. Hands-on walkthrough: `TESTING_GUIDE.md`;
  tier details: `tests/README.md`; install layout: `packaging/README.md`.
- **`artifacts/` is gitignored and holds secrets** (authoring key, rubric) —
  never commit it, never copy it onto shared media.
- **nakon discipline:** `catalog list/show/check --json` are read-only and
  agent-safe; `build`/`deploy` mutate. boxbuilder shells out to nakon and
  `vulndb-cli`, never imports them. Scenario extras (`theme:`, `forensics:`
  blocks) and the `--json` stdout/stderr contract are documented in
  `boxbuilder/README.md` — link, don't duplicate.
- **`architecture.md` is authoritative.** Where it and intuition disagree,
  follow the doc or raise the conflict.
