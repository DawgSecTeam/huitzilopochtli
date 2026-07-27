# Huitzilopochtli

A security-hardening scoring engine for practice and competitions. Teams harden target systems against a checklist of security controls, and Huitzilopochtli collects evidence and produces a scored report. In the lineage of CyberPatriot (point-in-time hardening) and eCitadel/CCDC (continuous SLA + live adversary).

## Overview

Huitzilopochtli scores boxes in two modes:

- **Honor mode** — offline, self-paced. Ideal for take-home assignments, workshops, and solo practice. No network required; the box scores itself against a rubric it ships with. Untimed, no adversary.
- **Ranked mode** — an always-on engine that aggregates signed check-ins from multiple boxes. Supports timed scenarios, a live adversary, and a shared leaderboard. Keeps the answer key off the box. Built for team competitions and structured exercises.

Both modes share the same on-box collector: it gathers structured evidence and makes no scoring decisions. Only the evaluator's location (box vs. engine) and the rubric's location change between modes. See [`architecture.md`](architecture.md) for the full design spec.

**Trust model:** ranked mode is signed and tamper-evident *in transit*, but it is not cheat-proof — a box's facts are self-reported by an agent the operator has root over. It is intended for practice, workshops, and friendly leaderboards rather than graded assessments. See `architecture.md` §3 for the full trust discussion.

## Quick start

```bash
python3 --version        # 3.10+ required; built/tested on 3.14
pip install --user pytest
pytest                    # runs the full unit + integration suite
```

To run the agent on a box and generate a score report:

```bash
python3 packaging/build_zipapp.py   # builds dist/agent.pyz
python3 dist/agent.pyz --honor      # honor mode: collects evidence, scores locally
```

For a guided, hands-on walkthrough that exercises honor mode, ranked mode, and the report output, see [`TESTING_GUIDE.md`](TESTING_GUIDE.md) in this repo.

## Repo layout

| Path | Role |
|---|---|
| `common/` | Pure-stdlib shared schema, canonical serialization, vendored Ed25519 crypto, and the evaluator — scoring logic is byte-identical wherever it runs. |
| `agent/` | On-box collector/reporter; builds into the `.pyz` deployed to a box. |
| `engine/` | Ranked-mode server: enrollment, check-in, SLA ledger, adversary scheduler, leaderboard. |
| `authoring/` | Scenario compile + sign toolchain, run on the author's machine. |
| `packaging/` | Zipapp build, install, and re-arm/reset tooling for deploying the agent to a box. |
| `tests/` | Unit, integration, and Proxmox (live-infrastructure) test tiers. |

## Building & deploying the agent

```bash
python3 packaging/build_zipapp.py     # writes dist/agent.pyz
```

The zipapp bundles only `agent/` + `common/` (pure stdlib, runs anywhere `python3` is present — including musl/Alpine). See [`packaging/README.md`](packaging/README.md) for the full install layout, systemd/OpenRC unit files, and the take-home re-arm/reset flow.

## Documentation

- [`architecture.md`](architecture.md) — full architecture & implementation spec; source of truth for component contracts.
- [`TESTING_GUIDE.md`](TESTING_GUIDE.md) — hands-on manual walkthrough end to end.
- [`tests/README.md`](tests/README.md) — test suite tiers, including the Proxmox live-infrastructure tier.
- [`packaging/README.md`](packaging/README.md) — build, install, and re-arm/reset details.
