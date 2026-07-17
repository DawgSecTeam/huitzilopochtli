# Test suite

Three tiers. A root `conftest.py` puts the repo root on `sys.path`, so every
test imports `agent`/`common`/`engine`/`authoring` directly — no installed
package, no path hacking needed in individual test files.

## `tests/unit/` — fast, hermetic

No external processes; mocked `subprocess`/filesystem where the real thing
would be slow, flaky, or system-dependent (platform layer, package managers).
Real (but temporary/local) files and sqlite DBs where that's cheap and more
representative (checks, store). 254 tests, ~40s.

## `tests/integration/` — real processes, same host

Real subprocesses (`python3 -m agent`, `python3 -m engine.server`), real
sockets over `127.0.0.1`, real sqlite files, real signing/verification. No
external VM or network boundary. 24 tests, ~90s — dominated by
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

### `test_all_check_types_live.py` — PASSES (Ubuntu 24.04 full; Fedora 44 partial)

`test_local_honor_distribution.py` only ever exercised `file_regex`. This
file runs a scenario hitting all seven check types (`file_regex`,
`permission`, `user_group`, `service_state`, `package`, `http_uptime`,
`db_query`) in one pass against a real, freshly-cloned VM.

- **Ubuntu 24.04: 70/70.** All seven check types collect and score
  correctly against real OS state.
- **Fedora 44: 30/70** (only `file_regex`/`permission`/`user_group`, which
  need no subprocess or network call, pass). The remaining four score 0 for
  reasons confirmed to be template/environment facts, not product bugs:
  `crond` isn't active by default on this minimal cloud image; `rpm` isn't
  reachable via the guest-agent's exec PATH so `package_installed()`
  correctly falls back to `(False, None)` instead of erroring; and
  `http_uptime`/`db_query` both hit `errno 13 Permission denied` on
  outbound `connect()` — the same SELinux `virt_qemu_ga_t` confinement
  documented below for `test_ranked_two_machines.py`, now confirmed to block
  outbound `connect()` from *any* process the guest agent spawns, not just
  `agent.identity.enroll()`'s call site.

### `test_local_honor_distribution.py` — PASSES (Ubuntu 24.04 + Fedora 44)

Builds the real `.pyz`, pushes it + a compiled scenario to a freshly-cloned
VM via the guest agent, runs it with the VM's own system `python3`, and
confirms the report is correct. Alpine is skipped for now per instruction.

**Scope note**: installs to `/tmp/huitzilopochtli` rather than the production
`/opt/huitzilopochtli` path, and runs the agent directly rather than through the
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

**Update:** the Ubuntu template (vmid 9106) has since been rebuilt with
working cloud-init, fixing #1 -- confirmed empirically (both roles cloned
from Ubuntu now get distinct IPs). The test now uses Ubuntu for both roles
and gets past enrollment. It's still not fully green, though, for a
*third*, previously-undiscovered reason:

3. **From this dev environment, arbitrary VM ports on the Proxmox host's
   LAN (`10.0.0.0/24`) are not reachable at all** -- confirmed by testing
   against several already-running, unrelated production VMs (not just
   test clones): every port except the Proxmox API's own (`:8006`) gets an
   immediate TCP RST within ~35ms. Only the Proxmox API and the QEMU
   guest-agent channel (file-write/file-read/exec) are reachable from here;
   a raw HTTP client on this machine cannot reach a cloned VM's exposed
   port directly. This is exactly the network boundary
   `test_ranked_two_machines.py`'s engine/checkin polling needs (it must
   `GET /health` and `POST /checkin` from the test process, not just push
   files via the guest agent), so the test is blocked on network
   reachability from this specific dev environment rather than on anything
   in the repo. `test_local_honor_distribution.py` and
   `test_all_check_types_live.py` are unaffected because they only ever use
   the guest-agent channel, never a raw connection to a VM's IP.

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
- `guest_file_write` rejected any payload over 60KB base64-encoded --
  confirmed empirically (`400 Bad Request: value may only be 61440
  characters long`) pushing the ~200KB engine bundle tarball in
  `test_ranked_two_machines.py`. Proxmox's `agent/file-write` endpoint is a
  one-shot open+write+close wrapper with no append/offset parameter, so
  there's no way to send a payload over the cap in one call. Fixed by
  splitting into ≤45000-byte chunks written to separate temp paths, then
  reassembled with a guest-side `cat` + cleanup.

### Bugs found live in `tests/integration/` (not the proxmox tier) while debugging the above

While chasing the network-reachability issue above, the *unrelated*
`tests/unit`/`tests/integration` tiers were run alongside the proxmox work
and turned up two real, previously-undiscovered process-management bugs of
their own -- confirmed by tracing an actually-hung `pytest` process (a
still-running `python3 -m engine.server` child, parent blocked in
`anon_pipe_read`, via `/proc/<pid>/wchan` and `ps --ppid`), not just
inferred from reading the code:

- **`tests/integration/test_admin_endpoints.py` and
  `test_tls_and_secret.py`**: both files' engine-health-check fixtures did
  `assert ok, "... " + proc.stdout.read()` when the health poll timed out.
  `proc` is still alive at that point (that's what "never became healthy"
  means) -- `.read()` with no timeout blocks until EOF, which never comes
  from a live, still-running process. Any run where engine startup was
  even slightly slow (confirmed trigger: CPU contention from concurrent
  Proxmox VM work on the same box) hung the *entire* suite forever, not
  just the one test. Fixed by terminating the process before reading its
  output.
- **`tests/integration/test_ranked_loopback.py`**: `_EngineProc.__init__`
  waited for the "listening on" startup line via a blocking
  `self.proc.stderr.readline()` loop -- but `engine/server.py` prints that
  line (and its two warning lines) with plain `print()`, which goes to
  **stdout**, not stderr. Reading a separate stderr pipe the engine never
  writes to blocks forever, deterministically, on the very first
  `_EngineProc` construction (not a timing-dependent flake -- this is why
  three separate full-suite attempts all stalled at the exact same
  progress percentage). Fixed by merging `stderr=subprocess.STDOUT` and
  reading `self.proc.stdout` instead. A second, unrelated bug in the same
  file's `_run_agent`/`_stop_agent` pair surfaced immediately after fixing
  the hang: `tempfile.NamedTemporaryFile(..., text=True)` -- `text=` isn't
  a valid kwarg for that function -- and `_stop_agent` read back
  `proc._stdout_file`/`proc._stderr_file`, attributes that were never set
  (`_run_agent` only stored `_stdout_path`/`_stderr_path` after closing its
  handles). Fixed both: dropped the invalid kwarg, and `_stop_agent` now
  reopens the files by path to read them back.

After both fixes, `pytest tests/unit tests/integration` passes clean:
**278 passed in ~91s**, with no hangs.

### Setup used for the runs above

Credentials and template VM IDs (`ubuntu24.04`=9106, `fedora44`=109, tagged
`template` on Proxmox) were supplied directly. Alpine was explicitly
excluded from this pass. VM naming uses the `dawgtest-` prefix (mirroring
`workshop-vm-distribution`'s own `workshop-` convention); every test tears
its own clones down in a `finally` block regardless of outcome, confirmed
empirically to leave zero stray VMs after each run.
