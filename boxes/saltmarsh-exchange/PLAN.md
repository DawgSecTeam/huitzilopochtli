# Saltmarsh Exchange — IIS + FTP hardening box: design plan

Status: **authored** (scenario + nakon config + seeds + handbook + tests).
Not yet planted/sealed on Proxmox.

Lineage: modeled on the latest Windows box, `boxes/harborline-transit`
(2026-09-28, the pre-CDE capstone). Same ledger shape, tier weights,
penalty-guard pattern, forensics block, handbook discipline, and
`tests/unit/test_boxbuilder_*.py` contract — but the subject is the web/FTP
edge instead of Active Directory.

## 1. Why this box

Harborline proves out the whole Windows/AD hardening surface on a domain
controller. This box is the **web-tier** counterpart: a workgroup member
server running the agency's public IIS portal and its vendor FTP drop. Every
scored finding lives in the IIS/FTP stack or in an account/service that
directly supports it. Nothing here needs a domain, Group Policy, or Kerberos.

Narrative: the Saltmarsh Regional Water Authority runs a customer portal on
IIS and a vendor file drop on FTP. An intruder left the site running but
helpfully weakened almost everything around it. The team hardens the web tier
in place — the portal, the vendor drop, and the accounts behind them.

## 2. Ledger (the contract with players)

| bucket | count | points | total |
|---|---|---|---|
| EASY vuls | 14 | 2 | 28 |
| MODERATE vuls | 15 | 4 | 60 |
| HARD vuls | 8 | 8 | 64 |
| **vul checks** | **37** | | **152** |
| penalty guards | 3 | -10 when broken | 0 at baseline |
| forensics | 6 | 8 | 48 |
| **maximum** | | | **200** |

0-state (freshly planted, nothing hardened): **0 / 200**. All 37 findings
are either explicitly planted or an explicitly planted insecure default, and
the three guards (W3SVC, FTPSVC, portal site) are satisfied. There are no
"free" hygiene checks in the vuln bucket — a deliberate change from
harborline's three DC-service checks, so the baseline is exactly zero and the
report's first earned point is a real fix.

Tier weights are vermilion-relay's/harborline's: EASY 2 / MODERATE 4 /
HARD 8. The handbook repeats them.

## 3. Host and services

Workgroup `swa-web01` (no AD). Full clone of `windows-server-fix`
(Proxmox template 953), prepared per `boxbuilder/REDEPLOY.md` "Windows round":

- base template: `workshop-template-win2022-iis-ftp` (vmid 164) on the
  `wkshp-pool` SSD storage; it already carries Windows Server 2022, IIS +
  FTP, `sysadmin`, and OpenSSH Server
- local admin `sysadmin` / `Lighthouse2026!` (password reset during prep)
- OpenSSH Server + password auth (build transport)
- Python 3.12.10 at `C:\Python312` on PATH (boxbuilder's ssh provider gate)
- firewall rules for 22, 80, 443, 8080 (the 8080 rule is a *plant*)
- IIS + FTP roles pre-installed in the template; the base seed is idempotent
  and installs WebDAV/ASP.NET/management extras

Sites are created by `iis-ftp-base-win`:

| object | value |
|---|---|
| web site | `SaltmarshPortal`, root `C:\inetpub\saltmarsh\wwwroot`, host `portal.saltmarsh.local` |
| app pool | `SaltmarshPortal` (.NET v4, Integrated, ApplicationPoolIdentity, logging on) |
| app | `/backoffice` at `wwwroot\backoffice` (Windows auth, no anonymous) |
| FTP site | `VendorDrop`, root `C:\inetpub\saltmarsh\ftproot`, port 21 |
| FTP group/user | `SaltmarshVendors` / `ftp_vendor` (password `Kestrel2026!`) |
| FTP transport | FTPS with a `CN=ftp.saltmarsh.local` self-signed cert, `SslRequire` |
| FTP firewall | `SaltmarshFtpIn` scoped to `10.0.0.0/8` |

The base seed is the **business-functional baseline** and carries the planted
0-state for the site-level toggles (directory browsing, detailed errors, TRACE,
WebDAV, logging). The app-pool, binding, backoffice-auth, TLS, FTP and artifact
findings are set by the flip seeds; the absence-based findings (no HTTPS
binding, no HTTP->HTTPS redirect) are simply absent at baseline. Re-running
`plant` restores the 0-state rather than relying on image defaults, so the
harden→revert loop is reproducible.

## 4. Vulnerability → check matrix

`seed` is the nakon configuration that plants the insecure state; every row
has exactly one scored check that awards the opposite (hardened) state.
`-win` seed names live in `boxbuilder/vulndb_vuln_configs/`.

### A. Host accounts, services, exposure (9)

| id | tier | seed | hardened state scored |
|---|---|---|---|
| `local_admin_roster` | MODERATE | `local-user-win` (`svc_webdeploy`, `ADMIN_ADD=1`) | Administrators holds only `Administrator` + `sysadmin` |
| `webdeploy_account_disabled` | EASY | same | `svc_webdeploy` exists **and is disabled** |
| `guest_account_disabled` | EASY | `guest-enabled-win` | local `Guest` disabled |
| `ftp_vendor_not_admin` | MODERATE | `local-group-member-win` (`ftp_vendor` → Administrators) | `ftp_vendor` exists, enabled, not in Administrators |
| `wmsvc_disabled` | EASY | `wmsvc-enabled-win` | WMSVC not running **and** StartMode is not Auto |
| `admin_console_removed` | MODERATE | `iis-admin-console-win` | the `SaltmarshAdmin` site **and** its firewall rule are gone |
| `rogue_ftp_rule_removed` | EASY | `firewall-allow-rule-win` (`VendorFtpAlt`, 2121) | the rule is gone |
| `web_share_restricted` | MODERATE | `insecure-smb-share-quiet-win` (`SaltmarshWeb$`) | share removed **or** no `Everyone` ACE |
| `aspnet_debug_off` | EASY | `sensitive-file-win` (live `web.config`, `debug="true"`) | `debug="false"` in the portal `web.config` |

### B. IIS site / application configuration (20)

| id | tier | seed | hardened state scored |
|---|---|---|---|
| `dir_browsing_off` | EASY | `iis-hardening-off-win` | directory browsing off on the site |
| `detailed_errors_off` | EASY | same | `httpErrors errorMode` is not `Detailed` |
| `version_headers_removed` | EASY | same | no `X-Powered-By` / `X-AspNet-Version` / `X-AspNetMvc-Version` |
| `trace_verb_blocked` | EASY | same | TRACE is denied (explicit deny, or unlisted verbs denied) |
| `access_logging_on` | MODERATE | same | site W3C logging enabled |
| `apppool_least_priv` | HARD | same | app pool identity is `ApplicationPoolIdentity` |
| `apppool_integrated_pipeline` | MODERATE | same | app pool is Integrated (not Classic) |
| `wildcard_binding_removed` | MODERATE | same | no bare `*:80:` binding; a host-header binding exists |
| `https_binding_present` | HARD | same (removes HTTPS) | HTTPS binding **and** a port-443 SSL binding exist |
| `http_redirects_https` | MODERATE | same | `httpRedirect` enabled, destination is `https://…` |
| `tls_legacy_disabled` | HARD | same (TLS 1.0/1.1 on) | TLS 1.0 **and** 1.1 explicitly disabled |
| `isapi_cgi_locked_down` | MODERATE | same | unlisted CGI **and** ISAPI extensions denied |
| `webdav_disabled` | MODERATE | same (`authoring` on + rule) | WebDAV authoring off/absent |
| `backoffice_anonymous_off` | MODERATE | `iis-backoffice-open-win` | anonymous off **and** Windows auth on at `/backoffice` |
| `backoffice_basic_off` | MODERATE | same | Basic auth off at `/backoffice` |
| `backoffice_outside_webroot` | HARD | (base leaves the app under `wwwroot`) | the app points outside `wwwroot` and its content moved with it |
| `config_backup_removed` | EASY | `sensitive-file-win` (`web.config.bak`) | the backup file is gone |
| `portal_archive_removed` | EASY | `zip-archive-win` (`portal-source.zip`) | the source archive is gone |
| `git_dir_removed` | MODERATE | `sensitive-file-win` (`.git\config`) | the `.git` directory is gone |
| `webshell_removed` | HARD | `sensitive-file-win` (`diag.aspx`) | no unapproved `.aspx`/`.ashx` under the web root |

### C. FTP (8)

| id | tier | seed | hardened state scored |
|---|---|---|---|
| `ftp_anonymous_off` | EASY | `ftp-hardening-off-win` | anonymous authentication off |
| `ftp_anonymous_write_off` | EASY | same (`users=*` Read/Write) | no Allow rule grants Write to `*`/`?`/anonymous |
| `ftp_control_ssl_required` | HARD | same (`SslAllow`, no cert) | control channel `SslRequire` **and** a cert hash bound |
| `ftp_data_ssl_required` | MODERATE | same | data channel `SslRequire` |
| `ftp_user_isolation_on` | HARD | same (`mode=None`) | isolation is `IsolateRootDirectoryOnly`/`IsolateAllDirectories` |
| `ftp_root_acl_restricted` | MODERATE | `insecure-dir-acl-win` (`Everyone:(OI)(CI)F`) | no explicit `Everyone` ACE on the drop root |
| `ftp_firewall_scoped` | HARD | same (`RemoteAddress Any`) | rule gone, or remote scope is not `Any` |
| `ftp_cleartext_creds_removed` | EASY | `sensitive-file-win` (`outgoing\vendor-credentials.txt`) | the leftover credential file is gone |

### D. Penalty guards (3, -10 each when broken)

| id | guard |
|---|---|
| `penalty_w3svc_running` | the World Wide Web Publishing Service stays running |
| `penalty_ftpsvc_running` | the FTP service stays running (the vendor drop is a business function) |
| `penalty_portal_started` | the `SaltmarshPortal` site stays started |

## 5. Forensics (6 × 8 = 48)

Answers live only in the rubric / post-event answer key; the handbook never
names them and check displays do not print them.

| id | question (abridged) | answer | discovery |
|---|---|---|---|
| `fq_webdeploy_account` | unauthorized local account with a seat in Administrators | `svc_webdeploy` | `Get-LocalUser` / `Get-LocalGroupMember` |
| `fq_ftp_vendor_password` | cleartext vendor password left in the drop | `Kestrel2026!` | the leftover credentials file |
| `fq_db_password` | database password in the web config backup | `SqlS3rv1ce!2024` | the `.bak` file |
| `fq_apppool_identity` | account the portal app pool runs as | `LocalSystem` | IIS Manager / `Get-Item IIS:\AppPools\...` |
| `fq_webshell_name` | filename of the hidden command page | `diag.aspx` | sweep the web root for unapproved ASPX |
| `fq_admin_port` | non-standard TCP port of the undocumented admin console | `8080` | `Get-Website`, `Get-NetFirewallRule` |

`fq_webdeploy_account` is a known non-pure answer (its disable check names
the account, the harborline `sethc.exe` precedent); the other five are not in
any check body except `fq_admin_port`, which appears in the console check's
collect params because the port is the natural selector. None appear in a
`display:` string.

## 6. Planting order (nakon.json)

1. `iis-ftp-base-win` — roles, dirs, app pool, site, `/backoffice`, FTP site,
   group/user, ACLs, cert, secure settings, firewall.
2. `local-user-win` (`svc_webdeploy`, admin) → `local-user-enable-win` →
   `guest-enabled-win`.
3. `local-group-member-win` (`ftp_vendor` → Administrators).
4. `wmsvc-enabled-win`.
5. `firewall-allow-rule-win` (`VendorFtpAlt` 2121).
6. `insecure-smb-share-quiet-win` (`SaltmarshWeb$`).
7. `iis-hardening-off-win` — every IIS finding in one pass.
8. `iis-backoffice-open-win`.
9. `iis-admin-console-win` — 8080 site + rule.
10. file artifacts: live `web.config` (debug), `web.config.bak`, `diag.aspx`,
    `.git\config`, `vendor-credentials.txt`, `portal-source.zip`.
11. `ftp-hardening-off-win`.

Ordering rules that matter:

- the base creates every directory/account/site before any seed flips it;
- accounts exist before the group-add seeds;
- the IIS/FTP seeds and the file seeds run after the base;
- `ftp-hardening-off-win` runs last so it re-applies the broad firewall rule
  and anonymous authorization after any earlier network work.

Each IIS/FTP seed declares `depends_on: [{"name": "iis-ftp-base-win"}]`, so
selecting one alone still resolves the base first.

## 7. What changes from harborline (and why)

| harborline | saltmarsh | reason |
|---|---|---|
| DC promoted to `harborline.local` | workgroup member server | no AD needed for IIS/FTP |
| 80 checks, 366 max | 37 checks, 200 max | focused single-subject round; clearable in one sitting |
| 3 "hygiene" service checks award at baseline | no baseline-free vuls; 3 penalties instead | keep 0-state exactly 0 |
| 8 forensics | 6 forensics | tighter artifact set |
| `ActiveDirectory` checks, GPO/GPP, DCSync | IIS config, FTP config, certs, app pools | web-tier subject |
| `permission` checks for files | same, plus `file_regex` for `web.config` | smallest capable collector |
| no theme differences | identical `theme-*-win` flow | unchanged tooling |

Reused unchanged: tier weights, `solution:` answer-key convention, handbook
spoiler rules, `theme` block (Windows seeds), `box.yaml` provider shape,
penalty `expect.points: -10` mechanics, the `powershell_json` rc-trailer
discipline (`-ErrorAction Ignore`, never `SilentlyContinue`, one compressed
JSON document on stdout).

## 8. New catalog seeds

Generic/helper seeds added under `boxbuilder/vulndb_vuln_configs/`:

| seed | purpose |
|---|---|
| `iis-ftp-base-win` | install IIS/FTP/WebDAV/ASP.NET/management; build the business-functional baseline sites, pool, users, ACLs, cert, firewall |
| `iis-hardening-off-win` | flip the IIS site/pool/server toggles to the planted state |
| `iis-backoffice-open-win` | anonymous + Basic auth on at `/backoffice` |
| `iis-admin-console-win` | undocumented site on 8080 + its inbound firewall rule |
| `ftp-hardening-off-win` | anonymous auth + server-level `*` Read/Write, `SslAllow` with no cert, isolation `None`, Everyone on the drop root, firewall to `Any` |
| `wmsvc-enabled-win` | set the Web Management Service to Automatic and start it |
| `local-group-member-win` | add a local account to a local group (idempotent) |
| `local-user-enable-win` | re-enable a local account (the `local-user-win` update path never flips Enabled) |
| `insecure-dir-acl-win` | create a directory and grant `Everyone:(OI)(CI)F` |
| `zip-archive-win` | write a real one-entry ZIP (the exposed source archive) |

All are `platform: windows`, `type: powershell`, `run_as: Administrator`,
`-ErrorAction Ignore`-only, describe their vars, and name their paired check.

## 9. Build and validation

Authoring-only checks (runnable here, no Windows box):

```bash
python3 - <<'PY'
import yaml
from authoring.validate import validate_scenario_yaml
p='boxes/saltmarsh-exchange/scenario.yaml'
d=yaml.safe_load(open(p))
print(validate_scenario_yaml(d, p))
PY
pytest -q tests/unit/test_boxbuilder_saltmarsh_exchange.py
pytest -q tests/unit/test_authoring_readme_lint.py
python3 -m boxbuilder answer-key --scenario boxes/saltmarsh-exchange/scenario.yaml --json
```

On a real clone (needs `vendor/nakon/.env`, `VULNDB_UI_URL`, a prepared
clone, and the provider host set in `box.yaml`):

```bash
python3 -m boxbuilder compile --spec boxes/saltmarsh-exchange/box.yaml --json
python3 -m boxbuilder plant   --spec boxes/saltmarsh-exchange/box.yaml --json
python3 -m boxbuilder install --spec boxes/saltmarsh-exchange/box.yaml --json
# expect 0/200 at the planted baseline; play the answer key to 200/200;
# re-plant to return to 0/200; then package/seal.
```

Acceptance criteria:

1. `scenario.yaml` validates and compiles; no signed manifest or rubric
   contains a `solution:`; every `display:` starts with `EASY:`/`MODERATE:`/
   `HARD:` or `PENALTY:`.
2. The all-boxes README lint is clean (no forensics answer, no mutation
   command, no planted path in the handbook).
3. At the planted baseline the report scores exactly 0/200 and the portal +
   FTP service are up.
4. Applying each `solution:` reaches 200/200; re-running plant returns the
   box to exactly 0/200 across two passes.
5. Fresh-clone boot: the agent task fires, the theme (README.html, wallpaper,
   shortcuts) is in place, and the portal responds on port 80.

## 10. Risks / open items

- **Deployed as a template (2026-10-20).** Proxmox vmid 172
  `challenge-saltmarsh-exchange` on `wkshp-pool` (the workshop SSD pool),
  `untrustedbr,firewall=1`, tags `workshop`. Built from
  `workshop-template-win2022-iis-ftp` (164); the build clone was 169.
  Plant 22/22 steps, 0 failures. The planted baseline grades 0/200
  (0/152 vulns, 37 remaining, 0 penalties, 0 forensics). A five-fix probe
  (directory browsing, detailed errors, TRACE, WebDAV, FTP anonymous)
  graded exactly 12 points, and a re-plant restored 0/200. The sealed
  clone boot-verified at 0/200, then was converted to a template; the
  build VM was destroyed. Published on the live workshop portal
  (10.0.0.102:5000) through its official admin API
  (`POST /api/admin/provision`), which assigned the random pool code
  `YEV6G` "Saltmarsh Exchange": template 172, RDP access (verified on a
  disposable clone), group Challenge, public/dispenser, 1 VM, 2-hour
  links. The API provisioned vmid 1201 as a linked clone on the
  `wkshp-pool` SSD base (available 1); claim at `/claim?code=YEV6G`.
  A full answer-key play-through to 200/200 is still a post-deploy
  acceptance step. The seed comments record the
  platform constraints: FTP authorization is server-level (the base
  configures it at the root), the template locks per-site authentication
  and WebDAV authoring (the base unlocks them), site-level custom headers
  are planted at the server level, and the live `web.config` plant runs
  before the site-level flips so it cannot overwrite them.

- **Role install time.** `iis-ftp-base-win` may take several minutes on first
  run; pre-installing IIS/FTP in the template removes that from the loop.
- **App pool identity swap.** The planted `LocalSystem` pool is swapped to
  `ApplicationPoolIdentity` by the fix; the base grants `IIS_IUSRS` read on
  the web root first, so the site keeps serving.
- **FTP isolation.** Enabling `IsolateRootDirectoryOnly` moves a local
  vendor's home under `ftproot\LocalUser\ftp_vendor`; the base creates that
  directory so the hardened state still has a writable home.
- **TLS registry plant.** The TLS 1.0/1.1 keys are written explicitly so the
  finding has a real 0-state even on images whose defaults are already
  hardened.
- **Forensics on the account.** `svc_webdeploy` is named by its disable
  check; the question remains investigable in the report/handbook, and the
  post-event key documents the exception.
