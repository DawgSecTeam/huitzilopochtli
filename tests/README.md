# Test suite

Three tiers. A root `conftest.py` puts the repo root on `sys.path`, so every
test imports `agent`/`common`/`engine`/`authoring` directly — no installed
package, no path hacking needed in individual test files.

## `tests/unit/` — fast, mostly hermetic

No VM/network boundary; mocked `subprocess`/filesystem where the real thing
would be slow, flaky, or system-dependent (platform layer, package managers).
A few tests intentionally spawn a real short-lived process or loopback socket
to pin timeout/collector behavior. Real (but temporary/local) files and sqlite
DBs where that's cheap and more representative (checks, store).

## `tests/integration/` — real processes, same host

Real subprocesses (`python3 -m agent`, `python3 -m engine.server`), real
sockets over `127.0.0.1`, real sqlite files, real signing/verification. No
external VM or network boundary. ~4 minutes — dominated by the ranked
suites; every check-in round-trip pays a client-side sign + server-side
verify, see the Ed25519 note below.

Ranked suites (2026-09-23 round; matrix + round reports in
`RANKED_TESTING.md`):
- `test_ranked_loopback.py` — enroll on first boot, restart-without-re-enroll,
  SIGKILL-mid-checkin seq recovery, SLA accrual, offline queue-and-flush.
- `test_ranked_protocol_errors.py` — the whole wire surface: enrollment error
  paths, check-in check order, replay + `last_seq` echo, answer-key
  redaction on raw bodies, hostile/mistyped payloads, admin surface, GET
  routing.
- `test_ranked_resilience.py` — engine-restart persistence + box resume,
  verify-gate 503 backpressure under a 4-box volley, token-enroll race.
- `test_ranked_adversary.py` — directive delivery → sandboxed execution →
  at-most-once across resends/restarts; SLA DOWN + accrual freeze.
- `test_zipapp.py::test_zipapp_ranked_smoke` — the built `.pyz` ranked
  against a local engine with a signed manifest.

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
repo) to test what the fast tiers structurally cannot. Most interaction goes
through the QEMU guest agent API (file-write/file-read/exec). Two paths use
SSH instead: Fedora's guest agent is SELinux-confined to `virt_qemu_ga_t`
(no outbound `connect()`, unreadable parts of `/usr`, no writes to `/opt`),
and Windows needs a real Python install plus SFTP for the 270KB agent bundle.

```
pytest -m proxmox
```

Set `TEST_TEMPLATE_VMID_FEDORA=1016` (`base-fedora44-fix`; it has the cloud
`fedora` user) and `TEST_TEMPLATE_VMID_WINDOWS=953` in `tests/proxmox/.env`.
Both live tests clone, bootstrap, assert, and destroy their own VM.

### `test_all_check_types_live.py` — Ubuntu 24.04 and Fedora 44 both pass 70/70

`test_local_honor_distribution.py` only ever exercised `file_regex`. This
file runs a scenario hitting seven of the twelve registered check types
(`file_regex`, `permission`, `user_group`, `service_state`, `package`,
`http_uptime`, `db_query`) in one pass against a real, freshly-cloned VM.
`process_state`, `command_json`, `forensics_answer`, `powershell_json`, and
`registry_value` are covered live on Windows by `test_windows_live.py`.

- **Ubuntu 24.04: 70/70** over the guest-agent channel (no credentials).
  Ubuntu's `ssh.service` is socket-activated, so the active-service check
  uses `cron`.
- **Fedora 44: 70/70** over a root SSH session (`unconfined_t`), using
  `sshd`/`openssh-server`. The earlier 30/70 result was the guest agent's
  SELinux domain — outbound `connect()`, `rpm`, and `/opt` were denied to
  `virt_qemu_ga_t` — not a product defect. The helper generates an ephemeral
  Ed25519 key, sets the cloud user/root passwords through qemu-ga, uses a PTY
  `su` to append the key to `/root/.ssh/authorized_keys`, and runs the agent
  as root. (The PTY marker is produced by the root shell via `$(id -u)`; a
  plain marker matches the echoed command line and closes `su` before it
  writes the key.)

### `test_windows_live.py` — Windows Server 2022, 90/90 + real install

Runs nine live checks on a fresh clone of 953 (`workshop-template-windows`
lineage): `file_regex`, `permission`, `user_group`, `service_state`,
`process_state`, `registry_value`, `powershell_json`, `http_uptime`, and
`db_query`. Asserts `Total: 90` from the real agent zipapp under real Windows
Python. The fixture sets an Administrator/sysadmin password through qemu-ga,
adds the sshd firewall rule, then installs Python 3.12 over SSH (detached
installer + poll) and writes a `python.cmd` shim so `python` is on PATH for
boxbuilder. qemu-ga is used only for that one short bootstrap: this image's
qga can die mid-session, and SSH is unaffected.

`TEST_WINDOWS_PREPARED=1` tells the fixture that the template already has
the `sysadmin` account, the sshd firewall rule, and Python 3.12 on PATH
(the repo's local template 169 is prepared this way). It then skips qemu-ga
bootstrap and the Python install, which is both faster and far more stable --
this image's qemu-ga can die under guest-exec. Without the flag the fixture
bootstraps stock 953: one short `cmd /c` (netsh + net user), then Python over
SSH as a detached SYSTEM scheduled task (a 27MB synchronous download can
outlive the SSH channel and leave a 0-byte installer).

The install path is a second, opt-in test (`TEST_WINDOWS_INSTALL_HOST`, plus
`TEST_WINDOWS_INSTALL_PASSWORD` if not the default lab password). It does not
clone: point it at a prepared Windows box and it drives
`boxbuilder.pipeline.install_box` end to end -- place + `icacls`-seal
`C:\ProgramData\huitzilopochtli` (inheritance off, SYSTEM+Administrators),
skip the logon-popup hardening (`HUITZILOPOCHTLI_SKIP_WINDOWS_HARDENING=1`:
its Python MSI repair can block for minutes and is orthogonal to scoring),
register the SYSTEM `HuitzilopochtliAgent` task, run it once, and assert the
first report is 80/80 (the 8 non-HTTP checks; the direct test covers
http_uptime). It also exercises the reinstall clean: if the box already has
the agent task, `install_box` ends the task, kills its python process, and
removes the locked `.grade.lock` before re-placing files. Lab only: sets
`HUITZILOPOCHTLI_INSECURE_HOST_KEYS=1` because the host key is ephemeral.

### `test_local_honor_distribution.py` — PASSES (Ubuntu 24.04 + Fedora 44)

Builds the real `.pyz`, pushes it + a compiled scenario to a freshly-cloned
VM via the guest agent, runs it with the VM's own system `python3`, and
confirms the report is correct. Alpine is skipped for now per instruction.

**Scope note**: installs to `/tmp/huitzilopochtli` rather than the production
`/opt/.huitzilopochtli` path, and runs the agent directly rather than through the
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

### `test_ranked_two_machines.py` — unblockable now; needs BIND + a fresh look

The test code is believed correct (built and iterated against real
failures until each bug was fixed -- see below). Of the three original
blockers, #1 died with the 9106 template rebuild, #2 is avoided by using
Ubuntu for both roles, and #3 (dev-host reachability) was **resolved
2026-09-23**: the RST boundary is per-bridge (untrustedbr blocks, vmbr0 is
open — see item 3 below). To actually run it today: add
`HUITZILOPOCHTLI_BIND=0.0.0.0` to the engine env (post-default-loopback),
point `TEST_TEMPLATE_VMID_UBUNTU` at a live Ubuntu template (106; 9106 is
gone), and re-run. Original write-up:

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

3. **~~From this dev environment, arbitrary VM ports on the Proxmox host's
   LAN (`10.0.0.0/24`) are not reachable at all~~ (RESOLVED 2026-09-23 — the
   boundary is per-bridge, not host-wide)**: the original RST finding was
   real but its scope was misread. Production/workshop VMs sit on
   **untrustedbr** (firewalled workshop bridge) and do RST everything from
   here; build clones **rebridged to `vmbr0`** (the standard build-loop step:
   `pmx rebridge <vmid> --bridge vmbr0 --firewall 0 --yes`) are fully
   reachable from the dev host on arbitrary ports. Verified 2026-09-23 with
   curl to a cloned engine VM's `:8080` and ssh to a cloned agent VM's `:22`
   (see RANKED_TESTING.md). The ranked round's real-VM E2E ran exactly this
   way. If a two-VM ranked run fails to connect, check which bridge the clone
   is on before believing a reachability claim: `pmx status <vmid>`.

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
All collected default-tier tests passed (see the pytest summary; counts are
intentionally not hard-coded here).

### Setup used for the runs above

Credentials and template VM IDs (`ubuntu24.04`=9106, `fedora44`=109, tagged
`template` on Proxmox) were supplied directly. Alpine was explicitly
excluded from this pass. VM naming uses the `dawgtest-` prefix (mirroring
`workshop-vm-distribution`'s own `workshop-` convention); every test tears
its own clones down in a `finally` block regardless of outcome, confirmed
empirically to leave zero stray VMs after each run.
