# Huitzilopochtli

A security-hardening scoring engine. Teams harden a target against security controls; Huitzilopochtli collects structured evidence and produces a scored report. It scores *correct hardening* — it does not deploy vulnerabilities. Both modes share one on-box collector; only the evaluator's location and the rubric's location change.

## Modes

- **Honor** — offline, self-paced. The box scores itself against a rubric that ships with it. Untimed, no adversary.
- **Ranked** — an always-on engine aggregates signed check-ins from many boxes: timed scenarios, a live adversary, a central leaderboard, and the rubric never lives on the box.
- **Ranked competitions** — a public join page, per-player timed runs, self-reported scored services, and an admin console. See [`RANKED_COMPETITION.md`](RANKED_COMPETITION.md).

**Trust model:** ranked mode is signed and tamper-evident *in transit*, not cheat-proof — the facts are self-reported by an agent the box operator has root over. It is built for practice, workshops, and friendly leaderboards, not graded assessments. See [`architecture.md`](architecture.md) §3.

## Quick start

Requires Python 3.10+ (`pip install -r requirements-dev.txt`). boxbuilder also needs the vendored submodules and the gitignored `vendor/nakon/.env`; see [AGENTS.md](AGENTS.md).

Each box is a directory under `boxes/` with one `scenario.yaml` (the honor base
plus an optional `ranked:` block), the `nakon.json` it plants from, and a
minimal `box.yaml`. The authoring contract — every key, both build targets,
theming, forensics — lives in
[`boxbuilder/README.md`](boxbuilder/README.md#the-inputs-you-author).

Cross-check the pairing and build:

```bash
python3 -m boxbuilder lint --spec boxes/<box>/box.yaml
python3 -m boxbuilder build --spec boxes/<box>/box.yaml --image-out <box>.ova
```

`--mode ranked` builds the ranked target from the same scenario file; honor and ranked are separate box lineages. Provider address and password come from `--provider-*` or `$HUITZILOPOCHTLI_PROVIDER_*`, never from the committed spec. Promoting a build to a template: [`boxbuilder/DEPLOY.md`](boxbuilder/DEPLOY.md).

On the box the agent zipapp collects and reports; the same zipapp is the `huitz` terminal console:

```bash
python3 packaging/build_zipapp.py            # dist/agent.pyz
python3 dist/agent.pyz /path/to/agent_config.json
huitz score        # or: huitz watch / huitz forensics / huitz grade
```

## Repo layout

| Path | Role |
|---|---|
| `common/` | Shared schema, canonical serialization, vendored Ed25519 crypto, and the evaluator — byte-identical scoring logic wherever it runs. |
| `agent/` | On-box collector/reporter; builds into the `.pyz` deployed to a box. |
| `engine/` | Ranked-mode server: enrollment, check-in, SLA ledger, adversary scheduler, competitions, leaderboard. |
| `authoring/` | Scenario compile + sign toolchain, run on the author's machine. |
| `boxbuilder/` | Practice-box factory: pairs nakon-planted vulns with huitz scoring checks. |
| `packaging/` | Zipapp and engine bundles, init units, and re-arm/reset tooling. |
| `tests/` | Unit, integration, and live-infrastructure test tiers. |

## Documentation

[`architecture.md`](architecture.md) — source of truth for component contracts. [`CLI.md`](CLI.md) — `huitz` and `boxbuilder` command reference. [`boxbuilder/README.md`](boxbuilder/README.md) — authoring, modes, build workflow. [`boxbuilder/DEPLOY.md`](boxbuilder/DEPLOY.md) — clone → snapshot → deploy → verify → seal. [`RANKED_COMPETITION.md`](RANKED_COMPETITION.md) — operator runbook. [`packaging/README.md`](packaging/README.md) — install layout, units, re-arm/reset. [`tests/README.md`](tests/README.md) — test tiers, including live infrastructure.
