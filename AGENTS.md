# AGENTS.md

Guidance for agents (LLM or otherwise) working in this repo.

## What this repo is

**huitzilopochtli** is a security-hardening **scoring engine**. Teams *harden*
target systems; the engine collects evidence and produces a scored report. It
scores **correct hardening** — it does *not* deploy vulnerabilities. Two modes:
**honor** (offline, box scores itself) and **ranked** (a central engine
aggregates signed check-ins; rubric stays off-box). See `architecture.md` (the
source of truth) and `README.md`.

The thing that *deploys* vulnerabilities is the sibling repo **nakon**; the
vulnerability catalog is **vulndb-ui**. huitzilopochtli pairs with nakon via
**boxbuilder** (below) to create practice boxes.

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

## Working in this repo

- **Python 3.10+** (built/tested on 3.14). No `pyproject.toml`/`requirements.txt`;
  runtime on a scored box is **pure stdlib + vendored Ed25519** (a hard invariant
  so the agent zipapp is portable — Debian/Fedora/Alpine). Tests need `pytest`;
  authoring needs `PyYAML`; boxbuilder needs `PyYAML` (+ `paramiko` for the ssh
  provider).
- **No src-layout.** conftest.py puts the repo root on `sys.path`, so
  `import agent`, `import common`, `import boxbuilder` work everywhere.
- **Layout:** `common/` (shared schema + evaluator + crypto), `agent/` (on-box
  collector, ships as `.pyz`), `engine/` (ranked-mode server), `authoring/`
  (scenario compile + sign), `packaging/` (zipapp build + init units + re-arm),
  `boxbuilder/` (the practice-box factory).
- **Tests:** `pytest` runs unit + integration (Proxmox tier is deselected by
  default). boxbuilder tests: `tests/unit/test_boxbuilder_*.py` and
  `tests/integration/boxbuilder/`.
- **`architecture.md` is authoritative.** Where it and intuition disagree,
  follow the doc or raise the conflict.
