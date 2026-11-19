# Build plan — `gavelport-courthouse` (packed ranked Windows DC box)

Design plan for the Windows-DC packed ranked box that replays WRCCDC Inv#2 (`bugs.acme.anvil`)
and MWCCDC Inv#2 (`AD-DNS.underpressure.local`). Source guidance: Nextcloud handoff pack
`/s/D9ZwnW5srEB6wEp` (zip, extracted to `/tmp/ncbox/2026-11-18-huitz-packed-box-invitationals-win/`):
spec `01-…`, machine-readable manifest `02-plant-manifest.csv` (74 rows), catalog gaps `03-…`,
provenance `04-…`, and two IR evidence docs under `source-evidence/`.

Status: **plan only — nothing built, catalog untouched.**

---

## 0. Verified facts (probed live, 2026 build-day)

| Check | Result |
|---|---|
| Repo baseline (`python3 -m boxbuilder lint --all`) | green — all 19 boxes ok, warnings only |
| Catalog `http://10.0.0.121:3000/api/configurations` | reachable; 359 entries |
| Manifest's 70 existing config names | 61 have real scripts (≥200 chars); 6 are real one-liners (`Enable WinRM`, `guest-enabled-win`, `local-user-enable-win`, `lsa-ppl-off-win`, `ntlm-downgrade-win`, `rdp-group-member-win`) — all fine |
| The 4 NEW configs (`dsinternals-dnscache-module-win`, `dns-query-logging-off-win`, `domain-password-pattern-win`, `administrator-weak-password-win`) | **confirmed still absent** — hard prerequisite |
| `windows-ssh-authorized-keys` | **still ships the literal placeholder key** (`c3rberusPlantedKeyPlaceholder…`) — blocks W6-04 + forensics `fq-ssh-key-comment` |
| Manifest var coverage | every `required_vars` of every existing config is provided by the manifest — no var gaps |
| Proxmox template `170` | exists, currently named **`workshop-windows-ad`** (handoff's name `Copy-of-VM-Windows-AD-Workshop` is stale; VMIDs recycle, as the handoff itself warns); `ostype win10`, on `untrustedbr,firewall=1` |
| Proxmox fallback `999 workshop-template-windows-ad` | **does not exist** — closest real alternative is **124 `workshop-template-windows-ad`**; also 953 `base-windows-server`, 164 `workshop-template-win2022-iis-ftp` (IIS+FTP roles) |
| Linux twin templates | 219 `huitz-ranked-acme-underpressure-template` (+`-prev2/-prev3`) — naming/email to mirror for the Win box |
| Windows platform support in repo | real and tested: `agent/platform/windows.py` (CIM services, HKLM packages, `run_ps`), `powershell_json`/`registry_value`/`user_group`/`service_state`/`file_regex`/`permission`/`process_state` Windows branches, 7 existing `windows-server` boxes (largest `harborline-transit`: 52 configs / 83 checks), Proxmox live Windows tier | 
| Handoff ranked-sketch vs real schema | sketch is draft-shaped and **will not compile as written**: real service types are `tcp_port`/`http_uptime` (not `tcp_open`); adversary vocabulary is only `flush_firewall`/`kill_service`/`drop_inert_artifact` (no `reassert`; `flush_firewall` is iptables/nft — a **no-op on Windows**); pool fields are `template_vm_id`/`template_vm_access_method`/`template_vm_username`/`template_vm_password` + `vm_count`/`guac_link_ttl_seconds` (not `{template, ttl_hours}`) |
| Forensics answers file on Windows | current agent resolves `Forensics-Questions.txt` to the primary desktop user's Desktop (Public Desktop) automatically — no explicit `path:` needed (harborline sets none) |
| `prohibited`/`penalty` categories | exist in `common/schema.py` (`vuln`/`penalty`/`prohibited`) — the spec §5 "penalty for service-kill" is expressible |
| boxbuilder | `REDEPLOY.md` referenced by the proxmox-ops skill **does not exist** in-repo; the deploy loop source of truth is `boxbuilder/DEPLOY.md` + `RANKED_COMPETITION.md` §3 |

---

## 1. Phase 1 — Catalog authoring (critical path; unblocks `plant`)

Owner: build agent. Tool: `vulndb-cli` (vendored) + JSON seeds in
`boxbuilder/vulndb_vuln_configs/` (`create-if-missing` trap: edit the seed, run `vulndb-cli update`).
Contract per config: `name`, `description`, `required_vars`, `platform: windows`, `category`,
`depends_on`, idempotent PowerShell `script`, `run_as: root` (SYSTEM on Windows).

### NEW-1 `dsinternals-dnscache-module-win` (W1-02)
- `required_vars: MODULE_DIR` (default the `WindowsPowerShell\v1.0\Modules\DNSCache` path), `BOOTSTRAP_BODY`.
- Script: create module dir; write `DNSCache.Bootstrap.psm1` whose error strings/function names
  reference `Get-ADDBAccount` / `Get-ADReplAccount` / `Get-ADDBBackupKey` (catchable by content) +
  a placeholder `DSInternals.PowerShell.dll`. Idempotent.
- Trap to keep: module named benignly `DNSCache`; the paired check requires the **directory gone**,
  and no `.psm1` under `Modules` referencing `Get-ADDBAccount` — deleting only the `.dll` must not score.

### NEW-2 `dns-query-logging-off-win` (W1-05)
- No vars. `EnableQueryLogging=0` under `HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters`
  (+ DNS-server-query-logging equivalent). Check: `registry_value` `EnableQueryLogging = 1`.

### NEW-3 `domain-password-pattern-win` (W1-06)
- `required_vars: ACCOUNTS` (csv `sam:pwd` ×3), `PATTERN` (default `^[A-Za-z]+!Acme\d{4}$`).
- Script: create `daffy.duck`/`lola.bunny`/`foghorn.leghorn` if absent, set their `Name!AcmeNNNN` passwords.
- Trap: the pattern spans 3 accounts; `fq-pattern-user` needs exactly one account at `Daffy!Acme4103`.

### NEW-4 `administrator-weak-password-win` (W1-08)
- `required_vars: ADMIN_PASSWORD` (default `Acme!Admin2026`).
- Script: `Set-ADUser Administrator -Reset …`. Check pairing must be **`lastpwdset` newer than build
  date** — a real rotation, not a planted-value string compare (a no-op could pass that).

### NEW-5 (recommended addition) `domain-host-secondary-nic-win` (W5-10)
- The existing `domain-host-on-wan-subnet-win` **repoints the first Up adapter's IPv4** (verified
  script: `Remove-NetIPAddress/Remove-NetRoute` then `New-NetIPAddress` on the first adapter) — as-is
  it can break build/scoring connectivity. No current box uses it. Rather than adapting at the box,
  author a variant that configures an existing **second** NIC (`INTERFACE_ALIAS` var) on the WAN range
  with the external DNS; no-op with a loud warning if only one NIC exists. (Same intent as the gaps
  doc's fix, implemented in the catalog rather than per-clone.)

### Fix `windows-ssh-authorized-keys` (W6-04)
- Replace the placeholder with a real generated ed25519 public key; add `required_vars: PUBLIC_KEY`.
- Generate the keypair offline; the **comment is the `fq-ssh-key-comment` answer**; private key stays
  in `artifacts/` (gitignored, 0600).

Acceptance: `nakon catalog check --select dsinternals-dnscache-module-win,dns-query-logging-off-win,
domain-password-pattern-win,administrator-weak-password-win,domain-host-secondary-nic-win --json`
passes; re-run the manifest-vs-catalog coverage script (var coverage stays at zero gaps).

Then fold the 8 "note/fix" advisories from the gaps doc into the box README build notes:
`MSSQL`/`remote-admin-duplication-win`/`mailenable…`/`wing-ftp…` are excluded by design (§7 of spec);
`Disable System Firewall` pushes its state to AD computers over WinRM (single-DC box → only itself);
`krbtgt-account-disabled-win` is **intentionally** plant-like (forces the W2 NTLM trail) — never
pre-fix it at build time, the player re-enables it (the check *is* "krbtgt enabled");
`windows-scheduled-log-clear`'s task name is hard-coded `WinDefSvcHelper` — keep the hidden task's
`TASK_NAME=\TheMostSecureUpdate` explicit so they never collide.

---

## 2. Phase 2 — Repo authoring: `boxes/gavelport-courthouse/`

Four files (layout identical to every box; canonical field list in `boxbuilder/README.md`):

```
boxes/gavelport-courthouse/
  box.yaml        # scenario: scenario.yaml; nakon_config: nakon.json; provider: {name: ssh, user: <admin>}
  nakon.json      # 1 machine, os: windows-server, configurations[] = the 74 manifest rows (name + vars)
  scenario.yaml   # scenario + 74 checks + theme + forensics(10) + ranked block
  assets/         # logo.png, wallpaper.png, README.md (the handbook)
```

### 2.1 box.yaml
No host, no password, no mode. `provider.user` = the admin boxbuilder will SSH as — note the AD
consequence: after promotion, local accounts stop authenticating; installs run as the domain
`Administrator` (or a domain admin), see `RANKED_COMPETITION.md` §"AD scenarios".

### 2.2 nakon.json
- `machines[0].os: "windows-server"` (drives boxbuilder's os_family → Windows install dir/task logic).
- One configuration entry per manifest row, exact `name` + `vars`, `ip/user/password` left as
  `REPLACED-BY-PROVIDER` placeholders (verified convention from the twin/harborline).
- Pairing: nakon.json carries **no check references** — lint pairs mechanically by planted artifact
  paths; `powershell_json`-style pairings (e.g. AD group members) will surface as "confirm used"
  warnings — review them, don't chase them to zero (harborline/meridian carry the same class).

### 2.3 scenario.yaml
- **`scenario.name` = `Gavelport Courthouse`** (renamed at the build decision: distinct from the
  Linux twin's `Acme Underpressure`; the engine keeps one current version per scenario name — two
  names here by design). `version: 1`, `mode: honor`, `hosts: [localhost]`.
  **Rebrand scope:** box directory, scenario name, theme title/organization/logo/wallpaper/accent,
  handbook story (Gavelport Municipal Court records network), pool var names, ranked-template name.
  The pack's non-negotiable #2 in-box artifact names are unchanged: `speedy.gonzales`,
  `marvin.martian`, `\SecureUpdate`/`\SuperSecureUpdate`/`\TheMostSecureUpdate`, the `DNSCache`
  module path, `svc-all`, the `Name!AcmeNNNN` password pattern, `C:\Windows\uts.ps1`,
  `MeshCentral`/`MeshAgent`, `IIS_IUSRS` — students must be able to pattern-match the real range.
  The AD domain DNS name is inherited from the base template (re-promotion is out of scope).
- **74 checks**, ids `w1_01…w6_08` (prefix+number mirrors the manifest; sibling style to the twin's
  `e1_01…`). All `category: vuln`, 5 pts, `timeout_s` 20–45. Type mapping from the manifest:
  - `powershell_json` (36): AD module steps get `Import-Module ActiveDirectory -ErrorAction Ignore`
    and fail closed (harborline's `domain_admins_subset` is the pattern to copy verbatim for W3-01/02;
    W3-03 DCSync = `Get-Acl` domain root Replication ACE; W3-04 = `Get-Acl` on AdminSDHolder;
    W3-10 RID hijack = SAM `F`-value read via registry — agent runs as SYSTEM so `HKLM:\SAM\SAM` is
    readable; W1-08 = `Get-ADUser Administrator -Properties PasswordLastSet` vs build date).
  - `registry_value` (13): current UAC/NLA/WDigest/AFEO/AppInit/AlwaysInstallElevated patterns.
  - `service_state` (2): W1-01 MeshAgent (absent/stopped + binary gone — EFI the binary path too),
    W4-12 `WinCryptSvc32` (SD reset then removed).
  - `file_regex` (4) / `permission` (4) / `user_group` (2): check these read Windows paths with the
    agent's Windows branches (indexed in `tests/unit/test_windows_support.py`).
- Every planted primary artifact path must be read by its paired check or a forensics question —
  the same rule lint enforces; this is where the 74 first maps to the authored checks.
- **services** (6) mirroring harborline's block (real schema!):
  `rdp` 3389, `dns` 53, `ldap` 389, `kdc` 88, `smb` 445 — `tcp_port`, `interval_s: 30`,
  `points_per_interval: 2`, `max_intervals_per_checkin: 3`; `iis` — `http_uptime` on
  `http://127.0.0.1/`, `interval_s: 60`. A DC service going dark then scores twice (SLA + the
  vuln-fix check), which is the intended "penalty" shape from the spec §5.
- **adversary**: recommend starting with **no events**. W4's `\SecureUpdate` / priv-user-respawn /
  mutual-watchdog plants already self-heal on their own timers; an engine-side `reassert`-style
  schedule would be a second replant source (the handoff's own warning: "two replant sources make
  scoring noisy"). The one engine action worth considering later is `kill_service` (Windows: `sc.exe
  stop`, works) on a service a plant owns, `affects_check` set; **never schedule `flush_firewall`
  here — it is a POSIX iptables/nft action and a silent no-op on Windows.** Revisit after the first
  field round.
- **forensics** (10 × 10): the exact ids/questions from the handoff §4, each with `answer` +
  tight `answers` aliases (e.g. `speedy.gonzales` vs `Speedy Gonzales`) and a `solution:` walkthrough
  (feeds `answer-key`, stays engine-side). Set nothing for `path:` — the current agent resolves the
  Public Desktop automatically.
- **theme**: `title: Gavelport Courthouse`, `organization: Gavelport County Municipal Court`,
  accent `#8C1F28` (judicial oxblood — distinct from every existing box), new `assets/` art
  (gavel/court-seal logo, records-room wallpaper); handbook `assets/README.md` written to the
  `HANDBOOK_GUIDE.md` bar (chocolate-factory skeleton; ground truth = roster: daffy/lola/foghorn as
  legitimate clerks, `svc-all` documented as the facilities service account; **must state the box
  arrives dirty — that is the point**; zero command blocks; no planted artifact names — the handbook
  never says "ACME" as the org story: the org is Gavelport, the artifacts carry the range's names).
  Compile runs `readme_lint`: forensics answers verbatim = hard fail, lesser leaks = warnings.
- **`ranked:` block**: `engine_url: http://127.0.0.1:8080` (committed loopback placeholder), the
  services block above, adversary (empty events), and
  ```yaml
  pool:
    template_vm_id: "${HUITZILOPOCHTLI_GAVELPORT_COURTHOUSE_POOL_TEMPLATE_VM_ID}"
    template_vm_access_method: rdp     # portal runs `python <agent>.pyz join` on VM open
    template_vm_username: "${..._USER}"
    template_vm_password: "${..._PASSWORD}"
    vm_count: 4
    guac_link_ttl_seconds: 14400       # 4h, per the handoff's ttl_hours
  ```
  (scenario-specific var names — the lint output already shows that convention for multi-box engines;
  deployment values land in the engine's `/etc/huitzilopochtli/pools.yaml` keyed by scenario name).

### 2.4 Tests
`tests/unit/test_boxes_contract.py` pick-up the new box automatically (compile/determinism/arithmetic/
no-answer-key — nothing to add for the floor). Add `tests/unit/test_gavelport_courthouse.py` for
the box-specific invariants, birchwood-academy style:
- ledger arithmetic: 74×5 + 10×10 = 470 + service SLA;
- W3-01/02's check reads exactly the two stray DA names (and tolerates removal in either order);
- no scored service is killable by any plant payload (the iis/http checks vs W5 plants: webshell is
  removed but IIS stays up — payload tasks must not target the six service endpoints);
- handbook contains no forensics answer strings (beyond `readme_lint`);
- every manifest plant maps to exactly one check id.
Gate before any VM work: `pytest tests/unit -q` green and `python3 -m boxbuilder lint --all` clean of
*errors* for this box (warnings reviewed against the accepted classes above).

---

## 3. Phase 3 — Base prep (Proxmox, live)

1. **Live-verify the base, by content.** Candidates today: 170 `workshop-windows-ad` (the JJ49Y
   pool source per the handoff — confirm the portal's pool config actually names 170's current
   incarnation before trusting it) and 124 `workshop-template-windows-ad` as fallback. Verify on a
   throwaway clone that it is genuinely a DC: `Get-ADDomain` DNSRoot, `Get-Service NTDS` running,
   `C:\Windows\NTDS\NTDS.dit` exists. **Never clone a workstation Windows template (903 lineage /
   191) — W3 needs AD DS.** If IIS/FTP roles are absent, install them during prep (the way 164 was
   built from 953).
2. Full clone → `gavelport-courthouse-build-01` (`pmx clone <vmid> <name> --full`; ~35–40 min for
   a 32G-class disk).
3. Bootstrap in the windows-round order: `wait-agent` → exec check → `set-user-password`
   (Administrator first — promotion refuses a blank one) → `wait-ip` → confirm OpenSSH + a real
   Python are present (bake both into the template; SFTP the python.org installer,
   `/quiet InstallAllUsers=1 PrependPath=1`, during prep — it cannot be installed per-clone) →
   create the scenario admin account → snapshot `pre-deploy-clean`.
4. DC cautions that remix the standard loop: SSH/RDP resets for minutes after DC boot (AD starting —
   `pmx wait-ssh` handles it; never hammer retries); shut the DC down before snapshot/clone (a live
   clone rolls AD back); first-boot stalls 25–40 min are LVM, not a wedge; check `slmgr /dli` —
   evaluation guests that fail activation shut down hourly (`wlms.exe` 1074).
   Sysprep decision: scoring identity is `identity.json` at `huitz join`, so generalization is
   optional; if used, only from a disposable never-domain-joined clone.

**Snapshot ordering (the one handoff contradiction to resolve):** its step 2 snapshots
`pre-deploy-clean` *after prep*, step 5 says take it *after the W1 image items*. Resolution for the
plan: prep → first full plant (all 74) → snapshot `pre-deploy-clean` → install → seal. A re-plant on
a clone of that snapshot then restores the full "arrive-owned" state (MeshCentral, DNSCache module,
gutted logging, weak patterns included). Document the arrive-dirty property in the box README.

---

## 4. Phase 4 — Plant, install, verify, seal

```bash
export VULNDB_UI_URL=http://10.0.0.121:3000     # the stale-URL trap: nakon/vulndb-cli silently
                                                 # fall back to 127.0.0.1:3000
export HUITZILOPOCHTLI_PROVIDER_HOST=<clone ip>  # or --provider-host at each step
export HUITZILOPOCHTLI_PROVIDER_USER=<admin user>
export HUITZILOPOCHTLI_PROVIDER_PASSWORD='...'
python3 -m boxbuilder compile --spec boxes/gavelport-courthouse/box.yaml --rebuild-bundle --json
python3 -m boxbuilder plant   --spec boxes/gavelport-courthouse/box.yaml --json
python3 -m boxbuilder install --spec boxes/gavelport-courthouse/box.yaml --mode ranked \
  --competition --json --provider-host <clone ip>
```

- `--competition` (not a plain ranked install): no upload, no enrollment token, agent task placed
  **disabled**; no rubric/`identity.json`/reports on the box — the engine parses `boxes/` itself.
- Plant health gate before seal: named plants provably exist on the box (`daffy.duck` present,
  `C:\Windows\uts.ps1`, `\SecureUpdate` task, `DNSCache` module dir, `MeshAgent` service…) — an
  install-only template binds and scores **vacuously** (RANKED_COMPETITION §3), so this check is
  mandatory.
- `python3 -m boxbuilder verify --spec … --mode ranked --competition --for-seal` then
  `seal-prepare --yes`. On Windows: verify skips journald/machine-id/X checks; check the
  `HuitzilopochtliAgent` task state (`schtasks /query /tn … /v`, last result 0, next run advancing);
  answers file on the **Public** Desktop writable by Users; install dir ACL-sealed to SYSTEM+Admins.
- Seal (hypervisor side per `boxbuilder/DEPLOY.md` Step 4): snapshot-delete → `shutdown /s` (not a
  hard stop — dirty bit + Shutdown Event Tracker modal on every clone) → rebridge **back to
  `untrustedbr,firewall=1`** → convert to template → rename
  **`huitz-ranked-gavelport-courthouse-template`** (mirroring the twin's 219 convention).
  Keep `pre-deploy-clean` available for rebuilds until the field round confirms.

Handoff's transient-spec note: plant/install accept a temp spec with the clone's DHCP address —
pass provider values by env/flag instead; nothing address-bearing is ever committed.

---

## 5. Phase 5 — Full-marks round-trip, registration, field round

1. **Fresh-clone test round** (full clone of the sealed template on the same bridge; second engine
   host if the bridge can't also reach the engine — seal must have happened on a network that
   reaches the engine): create a draft competition named for the test, pre-deploy or claim, open the
   VM (preflight: `python C:\ProgramData\huitzilopochtli\agent.pyz join --code <code>` runs on open
   for rdp pools), **wait 3–5 min for the first check-in** (a 90-check Windows rubric takes minutes
   to first score — verified mistake to make: declaring it unscored after 90 s).
2. Assert the landed baseline: **0/74 vuln checks, forensics 0/10, services green**, board stable.
3. Run the scripted hardening (scratchpad script, never committed): Rotate the W1 weak-pattern
   passwords (`Set-ADAccountPassword`, incl. Administrator — the check keys on `lastpwdset`), remove
   both strays from Domain Admins (`Remove-ADGroupMember`), revoke DCSync ACE, purge AdminSDHolder
   ACE, re-enable krbtgt, delete GPO+payload, clear delegation, fix RID/Guest, disable rogue computer,
   remove all W4 persistence (deny-delete file needs `icacls /reset` or take-ownership **before**
   del; `WinCryptSvc32` needs `sc sdset` back to a normal SDDL **before** `sc delete` — wait ≥2
   cycles past the 60-s respawn before asserting), tear down the IIS plants, W5 shares/ports,
   W6 items. Known Windows gotchas batch: `Set-MpPreference` re-enable, DNS query logging keys,
   IFEO `Debugger` values, WMI `__FilterToConsumerBinding` + namespaced filter/consumer, runkey +
   startup + winlogon Userinit restore (`userinit.exe,` suffix discipline), AppInit/AppCert, autologin
   keys, `LmCompatibilityLevel`/WDigest/LDAP signing/anonymous tokens + SAM enum/SMBv1, GPP
   `cpassword` (remove the GPP or the field), uts.ps1 + corpus creds, secondary NIC removal,
   ` administrators_authorized_keys` empty (watch inheritance/ACL), locked service + the two SMB
   shares, RDP-Tcp2, `svc_intake`/`acmedeploy`/`svc_helper` + respawns, execution policy set.
4. Assert full marks: 370 + 100 + service SLA ticks accumulate; fix the *authoring* if a check is
   wrong (never weaken it to pass the script); re-run the round-trip once clean.
5. **Registration:** engine-side `pools.yaml` entry keyed by the new scenario name ([rdp, template
   vmid, admin, password]; 0600, readable by the engine user) + the `${…}` vars for CI compile; box
   README (handoff's step-5 arrive-dirty note + the 148 plant→check pairing table); the external
   registry note `services/gavelport-courthouse.md` per team convention (the handoff's step-8 item —
   no in-repo services/ registry exists; confirm destination with the portal owner). Patch the portal
   `pool.json` if that is the club's mechanism for pool templates.
6. **Field round:** run a real competition on the pool; keep `acme-underpressure` (Linux) untouched;
   retire the `-prev` templates only after field confirmation.

---

## 6. Effort sketch

| Phase | Work | Rough size |
|---|---|---|
| 1 | 5 catalog configs + 1 fix + seeds | half a day (CLI round-trip + review) |
| 2 | 74 checks + 10 fq + theme + handbook + tests | the long pole: 2–4 sessions; harborline (83 checks) is the density/style reference |
| 3 | clone + prep + snapshot | 1 session, mostly waits (35–40 min clone; DC boot patience) |
| 4 | compile/plant/install/verify/seal | 1 session; plant is idempotent, navvigate warnings |
| 5 | round-trip + registration + field | 1–2 sessions incl. fix loop |

Sequencing: Phase 1 first (everything else wall-chains on it), Phases 2–3 can interleave
(authoring on the dev host while the base clone preps).

## 7. Top risks

1. **`nakon.json` `os` value + handoff drift**: handoff names stale templates (170 renamed, 999 gone)
   — resolve by content, not VMID.
2. **Placeholder SSH key** ships in the live catalog — fix before W6-04/fq-ssh-key-comment.
3. **Kick-schema mismatch in the handoff** (`tcp_open`, `reassert`, `pool.template`) — the plan's §2.3
   shapes compile; anything else fails at `authoring/validate.py`.
4. **Vacuous scoring** is a seal-order trap: no plants on the template ⇒ every "absent" check passes.
5. **Two replant sources** (self-heal + adversary events) — start with no adversary events.
6. **flush_firewall no-op on Windows** and **AD auth windows after boot** — don't fight either.
7. **First-score latency** on an ~90-check Windows rubric (minutes) — budget patience in validation.
8. ** krbtgt**: intentional plant; never pre-fix at build time.

## 8. Range field test (2026-11-19, engine 10.67.2.2) — results

- Registered on the range engine `http://10.67.2.2:8080` (admin picker lists
  "Gavelport Courthouse|1"); pool entry in `/etc/huitzilopochtli/pools.yaml`
  points at template **vmid 108** (`huitz-ranked-gavelport-courthouse-range-v2`,
  vm2, DawgSec_Sandbox pool; 9600 kept as the pre-fix template, 419 as the
  original build VM). Portal: `http://10.67.70.254:5000`.
- **Manifest id remap gotcha (important):** the working tree carries an
  uncommitted "ranked anti-oracle" chk-NNN remap in `authoring/compile.py` +
  `common/scenario_record.py`. The deployed engine runs committed code and
  expects authored ids (`w1_01…`). A manifest compiled with the remap scores
  0 hardening ("missing field 'data'") against the deployed engine. The
  shipped manifest must use authored ids; do not deploy the remap without
  deploying the matching engine.
- **Signature gotcha:** `artifacts/*/authoring.key` is a hex-encoded 32-byte
  Ed25519 seed (see `boxbuilder/keys.py`); loading it as base64 produces a
  manifest that fails agent-side verification. Sign with
  `authoring.sign_scenario.sign_manifest` + hex-decoded key.
- **IIS 500.19 at seal time:** the SaltmarshPortal site root
  (`C:\inetpub\saltmarsh\wwwroot`) was missing and the only :80 binding was
  host-named. Fixed in template 108: hostless `*:80:` binding + index.html
  in site root. svc_iis then scored UP.
- **Field round 2** (`gavelport-field-round-2`, comp ebb485d4…): player join
  + claim + `agent.pyz join --code` + hardening + forensics answers →
  **hardening 460/465, forensics 10/10, all 6 services UP** (total 934 and
  accruing). Only `w3_08_krbtgt_enabled` stays red: AD refuses
  `Set-ADUser -Enabled $true` on krbtgt ("Cannot perform this operation on
  built-in accounts") on this build — flag as a scenario defect (either the
  plant should not disable krbtgt, or the check should accept the platform
  behavior). `w4_12_locked_service_removed` flapped once until the service
  was `sc delete`d (not just stopped).
- **Teardown verified:** ending the comp made the portal destroy only its own
  clones (442-444); templates 108/419/9600 untouched.
