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
clone real, disposable VMs on a Proxmox host (credentials read from a local
`tests/proxmox/.env`, gitignored, copied from `workshop-vm-distribution`'s
own `.env` values -- this repo never reads or modifies that other, unrelated
repo) to test what the fast tiers structurally cannot. All VM interaction
goes through the QEMU guest agent API (file-write/file-read/exec), not SSH.

```
pytest -m proxmox
```

### `test_local_honor_distribution.py` — PASSES (Ubuntu 24.04 + Fedora 44)

Builds the real `.pyz`, pushes it + a compiled scenario to a freshly-cloned
VM via the guest agent, runs it with the VM's own system `python3`, and
confirms the report is correct. Alpine is skipped for now per instruction.

**Scope note**: installs to `/tmp/dawgscore` rather than the production
`/opt/dawgscore` path, and runs the agent directly rather than through the
real systemd unit. This is because the Fedora template's `qemu-guest-agent`
runs SELinux-confined to the `virt_qemu_ga_t` domain, which is denied
writes to `usr_t`-labeled paths (`/opt`) and `/etc/systemd/system` even as
root (confirmed via `id` showing uid=0 and `ls -Z` showing DAC bits would
otherwise allow it -- this is SELinux denial, not a Unix permission issue).
`/tmp` (`tmp_t`) is allowed. This still exercises the thing process-level
testing on the dev machine cannot -- a real `.pyz` under a real system
`python3` on a genuinely separate, freshly-provisioned host -- just not the
systemd-registration step. Getting that would need a `semanage fcontext`
rule added to the shared Fedora template, a real change to shared
infrastructure this test suite doesn't make on its own.

### `test_ranked_two_machines.py` — BLOCKED on two infrastructure issues

The test code is believed correct (built and iterated against real
failures until each bug was fixed -- see below) but cannot currently pass,
for reasons outside this repo:

1. **Two clones of the same template collide onto the identical DHCP
   IP.** Confirmed empirically (`ip_a == ip_b` every time, with distinct
   MAC addresses ruled out as the cause): almost certainly the Ubuntu
   template's `/etc/machine-id` (and thus DHCP client-id) was never reset
   before it was converted to a template, so every clone presents the same
   client-id regardless of MAC. **This likely also affects
   `workshop-vm-distribution`** any time it provisions more than one VM
   from this template concurrently -- worth checking/fixing there too.
   Standard fix: boot the template once, `cloud-init clean --logs`, empty
   `/etc/machine-id`, remove any cached DHCP lease files, shut down, and
   re-convert to a template.
2. **The Fedora template's guest-agent-spawned processes cannot make
   outbound network connections.** Confirmed via a real failure:
   `agent.identity.enroll()` (a plain `urllib` HTTP POST) raised
   `URLError: <urlopen error [Errno 13] Permission denied>` when run via
   guest-exec on Fedora -- the same SELinux confinement noted above also
   denies outbound `connect()` for anything spawned through the guest
   agent, not just filesystem writes. (Confirmed this doesn't affect the
   honor-mode test above only because honor mode makes zero network
   calls.)

Working around #1 by using two *different* templates (Ubuntu engine +
Fedora agent, since the agent role never binds a port, only connects out)
ran into #2 instead. Using Ubuntu for both roles avoids #2 but hits #1.

**Options, in rough order of durability:**
- Fix the Ubuntu template's machine-id/cloud-init state (fixes #1, and is
  worth doing regardless of this test suite -- see above). Then use Ubuntu
  for both roles.
- Relax the Fedora template's SELinux policy for `virt_qemu_ga_t` (a
  `semanage` module permitting outbound connect, or `setenforce 0` for
  testing purposes) -- a real security-relevant change to shared
  infrastructure, needs an operator decision.
- Add SSH as a fallback transport for the agent role specifically (using
  `workshop-vm-distribution`'s `TEMPLATE_VM_USERNAME`/`TEMPLATE_VM_PASSWORD`
  convention), bypassing the guest-agent's SELinux domain entirely --
  more code, but requires no infrastructure changes.

None of these were applied without asking first, since they all touch
shared production infrastructure.

### Bugs found and fixed in this test tier itself, along the way

- `proxmox_helper.py::clone_vm` fired `status.start.post()` immediately
  after `clone.post()` without waiting for the (asynchronous) clone task
  to finish -- a real race condition, confirmed by `config.get()` on the
  "cloned" VM coming back with `net0` entirely absent. Fixed by polling
  each task's status to completion before proceeding.
- `guest_file_write` passed `encode=True`/`encode=1` while *also*
  pre-base64-encoding the content itself -- Proxmox's `encode` parameter
  means "please base64-encode the plain content I'm giving you", not
  "this content is already base64". Sending both meant the file written
  to the VM contained literal base64 text instead of the decoded binary.
  Fixed by encoding the content once and passing `encode=0`.
- `guest_file_read`'s `content` field is returned already-decoded (not
  base64, asymmetric with `file-write`'s input) -- confirmed empirically.
  Fixed to stop double-decoding it.
- `test_ranked_two_machines.py`'s leaderboard-polling loop didn't catch
  connection exceptions, so a transient hiccup mid-poll crashed the whole
  test instead of retrying.

### Setup used for the runs above

Credentials and template VM IDs (`ubuntu24.04`=9106, `fedora44`=109, tagged
`template` on Proxmox) were supplied directly. Alpine was explicitly
excluded from this pass. VM naming uses the `dawgtest-` prefix (mirroring
`workshop-vm-distribution`'s own `workshop-` convention); every test tears
its own clones down in a `finally` block regardless of outcome, confirmed
empirically to leave zero stray VMs after each run.
