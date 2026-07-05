# Test suite

Three tiers. A root `conftest.py` puts the repo root on `sys.path`, so every
test imports `agent`/`common`/`engine`/`authoring` directly — no installed
package, no path hacking needed in individual test files.

## `tests/unit/` — fast, hermetic

No external processes; mocked `subprocess`/filesystem where the real thing
would be slow, flaky, or system-dependent (platform layer, package managers).
Real (but temporary/local) files and sqlite DBs where that's cheap and more
representative (checks, store). 226 tests, ~40s.

## `tests/integration/` — real processes, same host

Real subprocesses (`python3 -m agent`, `python3 -m engine.server`), real
sockets over `127.0.0.1`, real sqlite files, real signing/verification. No
external VM or network boundary. 22 tests, ~3 minutes — dominated by
`test_ranked_loopback.py`, see the note below.

Run both tiers together (the default):

```
pytest
```

### Why this is slow: vendored Ed25519 performance

`common/crypto/ed25519.py` is a line-for-line Python 3 port of the original
public-domain reference implementation from `ed25519.cr.yp.to` (see that
file's docstring for provenance). That reference implementation is known to
be slow in pure Python — it recomputes a full modular inverse via
Fermat's-little-theorem exponentiation (~255 recursive squarings) *inside
every single elliptic-curve point addition*, rather than using a faster
extended-Euclidean inverse. Measured on this machine: **~0.6s per
`keypair()`, ~1.8s per `sign()`/`verify()`.**

This is why `test_ranked_loopback.py` alone takes ~85s (each check-in
round-trip costs a client-side sign + server-side verify, ~3.5-4s) and the
full integration tier takes ~3 minutes. It is a genuine, measured
performance characteristic of the exact reference implementation chosen —
not a bug, and not something this test suite works around, since
`tests/unit/test_crypto.py` pins the vendored implementation's *output*
against real RFC 8032 known-answer vectors (architecture.md §19). Swapping
in a faster (but still hand-verifiable) inverse algorithm is possible later
with that test as a safety net, but is out of scope for this suite — flag it
if per-check-in engine latency or per-box CPU cost becomes a real concern at
your target scale.

## `tests/proxmox/` — opt-in, live infrastructure required

Not run by default (`pytest.ini` excludes the `proxmox` marker). These
clone real, disposable VMs on a Proxmox host to test what the fast tiers
structurally cannot:

- `test_local_honor_distribution.py` — the actual `.pyz` + systemd/OpenRC
  unit running under a real init system on real Debian/Fedora/Alpine,
  including Alpine's `apk add python3` caveat (packaging/README.md).
- `test_ranked_two_machines.py` — the agent and engine on two genuinely
  separate hosts, crossing a real network boundary.

Run explicitly once configured:

```
pytest -m proxmox
```

**Setup required** (not yet provided — see `tests/proxmox/proxmox_helper.py`
for the exact env vars expected):

1. Proxmox API credentials (`PROXMOX_URL`, `PROXMOX_USER`,
   `PROXMOX_TOKEN_NAME`, `PROXMOX_TOKEN_SECRET`, `PROXMOX_NODE`) in a local
   `tests/proxmox/.env` (gitignored) — this repo does not read or modify
   `workshop-vm-distribution`'s `.env`, it's a separate, unrelated tool; copy
   the values over if reusing the same Proxmox host.
2. Template VM IDs for Debian, Fedora, and Alpine (each with
   `qemu-guest-agent` installed, matching the requirement documented in
   `packaging/README.md`'s Alpine caveat).
3. Confirmation that a single template is fine to clone twice for the
   two-machine ranked-mode test (engine host + agent host), or a separate
   longer-lived engine host if preferred.
4. Which network bridge/VLAN these disposable test VMs should attach to.
5. Confirmation that the `dawgtest-` VM name prefix (mirroring
   `workshop-vm-distribution`'s own `workshop-` safety convention) is an
   acceptable cleanup boundary — every test tears its own clones down
   in a fixture-teardown block regardless of outcome.

Until these are supplied, `tests/proxmox/` contains the helper scaffolding
and marker wiring but the two test files themselves are not yet written.
