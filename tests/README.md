# Test suite

Three tiers. A root `conftest.py` puts the repo root on `sys.path`, so every
test imports `agent`/`common`/`engine`/`authoring` directly — no installed
package and no per-file path hacking.

| Tier | Path | Needs | Run |
|---|---|---|---|
| Unit | `tests/unit/` | `requirements-dev.txt`; one test skips without root | `pytest tests/unit` |
| Integration | `tests/integration/` | loopback sockets; no network or root | `pytest tests/integration` |
| Proxmox | `tests/proxmox/` | `tests/proxmox/.env` + a reachable Proxmox host | `pytest -m proxmox` |

Default (`pytest`) runs unit + integration; `pytest.ini` deselects the
`proxmox` marker. One file or one area:

```bash
pytest tests/unit/test_authoring_validate.py -q
pytest tests/integration -q -k "ranked or competition"
pytest tests/integration/test_ranked_loopback.py -q
```

For counts, use `pytest --collect-only -q`; no number is hard-coded here.

## Unit tier

In-process and fast. Temporary files and sqlite DBs where that is cheap and
more representative; a few tests spawn a short-lived process or socket to pin
timeout/collector behavior, and the platform/package-manager layer is mocked.
Covers schema and type validation, canonicalization, every matcher and check
plugin, category scoring, crypto vectors, the SLA ledger, the adversary
allowlist/oracle, the store and migrations, competition and claim logic,
scenario-mode merging, authoring validation, and the handbook spoiler lint.

Boxbuilder has unit suites per box (`tests/unit/test_boxbuilder_<box>.py`) plus
the shared `test_boxbuilder_*.py` modules; these parse specs and compile
scenarios without touching a VM.

## Integration tier

Real subprocesses (`python3 -m agent`, `python3 -m engine.server`), real
sockets on `127.0.0.1`, real sqlite files, real signing and verification. No
external VM or network boundary and no root.

- Honor pipeline, admin endpoints, TLS/secret persistence, zipapp/source
  equivalence.
- Ranked loopback: first-boot enroll, restart without re-enroll,
  SIGKILL-mid-check-in seq recovery, SLA accrual, offline queue flush.
- Ranked protocol errors: enrollment and check-in ordering, replay/`last_seq`,
  answer-key redaction, hostile payloads, admin surface.
- Ranked resilience: engine-restart persistence, verify-gate 503 backpressure,
  token-enroll race.
- Ranked adversary: directive delivery and at-most-once execution, SLA outage
  floor.
- Competition surface: public join → signed `/join` → check-in → leaderboard →
  admin End, admin login/CSRF.
- `tests/integration/boxbuilder/` drives the pipeline against an in-process
  fake provider/SSH handle: compile/plant/install/package and competition mode,
  with no VM.

**Runtime is crypto, not a hang.** The vendored pure-Python Ed25519
implementation (`common/crypto/ed25519.py`) signs and verifies on every
check-in round-trip, so the integration tier takes minutes
(`test_ranked_loopback.py` alone is ~70s). It is deliberately not worked
around: `tests/unit/test_crypto.py` pins the implementation's output against
RFC 8032 vectors.

## Proxmox tier (opt-in, live infrastructure)

These clone real, disposable VMs and test what loopback cannot. They are
skipped with a reason when `tests/proxmox/.env` is absent. The `.env` is
gitignored — never commit it or copy values into docs.

| Variable | Purpose |
|---|---|
| `PROXMOX_URL`, `PROXMOX_USER`, `PROXMOX_TOKEN_NAME`, `PROXMOX_TOKEN_SECRET`, `PROXMOX_NODE` | API access; all five are required before the tier stops skipping |
| `TEST_TEMPLATE_VMID_UBUNTU` | Ubuntu template for the honor/check-type/ranked tests |
| `TEST_TEMPLATE_VMID_FEDORA` | Fedora template for the check-type and honor tests |
| `TEST_TEMPLATE_VMID_WINDOWS` | Windows template (defaults to the helper's built-in id) |
| `TEST_VM_PASSWORD` | Password set on throwaway clones |
| `TEST_WINDOWS_PREPARED=1` | Skip the Windows bootstrap when the template already has `sysadmin`, sshd, and Python on PATH |
| `TEST_WINDOWS_INSTALL_HOST` / `TEST_WINDOWS_INSTALL_PASSWORD` | Opt into the real boxbuilder install test against a prepared Windows box |

Requirements beyond the env file: API access to the Proxmox host, IP
reachability to the clones' bridge from the test host, and the QEMU guest
agent in the templates. This tier needs no root on the dev host; the one
root-only default-tier test skips otherwise. Most interaction
uses guest-agent file-write/read/exec; Fedora uses root SSH because its agent
is SELinux-confined (`virt_qemu_ga_t` denies outbound `connect()` and `/opt`
writes), and Windows uses SSH plus a real Python install.

- **`test_local_honor_distribution.py`** — builds the real `.pyz`, pushes it
  and a compiled scenario to a fresh clone, runs it with the VM's `python3`,
  and checks the report. Installs under `/tmp` and skips systemd registration
  (the Fedora guest-agent confinement again).
- **`test_all_check_types_live.py`** — seven check types in one pass on Ubuntu
  (guest agent) and Fedora (root SSH). Ubuntu's socket-activated `ssh.service`
  means the active-service check uses `cron`.
- **`test_windows_live.py`** — nine check types on a Windows Server clone plus
  an opt-in real install (ACL seal, SYSTEM scheduled task, first report).
- **`test_ranked_two_machines.py`** — engine and agent on two separate clones.
  Regenerates each clone's machine-id (Ubuntu templates have shipped with a
  duplicate, which collides on DHCP) and runs the engine with
  `HUITZILOPOCHTLI_BIND=0.0.0.0`.

Clones are named with a `dawgtest-` prefix and torn down in a `finally` block;
pick templates you can destroy, never production VMs. If a run cannot reach a
clone, check which bridge it was cloned onto before assuming a product bug.

## Conventions

- Tests own their temp state (`tmp_path`, ephemeral sqlite, free ports) and
  clean up clones; nothing under `artifacts/` is committed (it holds keys and
  rubrics).
- A new behavior gets a regression test that fails without the fix; a new box
  gets its unit suite and a `python3 -m boxbuilder lint --all` clean run.
