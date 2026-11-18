# Tamarack Regional Airport — template prep notes

Build order for a fresh clone of the Debian 13 CLI base (the
`base-debian13-lite-fix` lineage), following the Broadneck Post loop:

1. **Prep (this directory, as root over ssh):**
   ```sh
   sh 01-accounts.sh     # roster, hostname, timezone, build-time packages
   sh 02-portal.sh       # portal webroot + display feed directory
   ```
2. **Plant the red path** (installs nginx / PostgreSQL / Redis and every
   finding; see `../../nakon.json`):
   ```bash
   python3 -m boxbuilder compile --spec boxes/tamarack-airport/box.yaml --out artifacts/tamarack
   python3 -m boxbuilder plant   --spec boxes/tamarack-airport/box.yaml --out artifacts/tamarack \
       --provider-host <clone-address>
   ```
3. **The break-in** (drives the planted weak stack; MUST run after plant —
   it guesses `fieldsvc`, whose weak password only works once the respawn
   machinery has asserted it, and harvests the web-root leaks the plant
   drops):
   ```sh
   python3 85-skylark-replay.py
   ```
   It verifies itself: 1 accepted ssh password in the journal, 3
   alias-source lines in the nginx access log, `flightinfo` seeded.
4. **Install + verify + seal** per `boxbuilder/DEPLOY.md`. Ranked:
   add `--mode ranked --competition` and the engine URL; the pool block
   expands from `HUITZILOPOCHTLI_TAMARACK_AIRPORT_POOL_TEMPLATE_*`.

## Credentials

| account    | password          | role |
|------------|-------------------|------|
| flightops  | flightops         | player / ops desk lead (sudo) |
| root       | TamarackRoot2026! | build only — never in the handbook |
| fieldsvc   | SkylarkField22!   | the contractor's weak account (planted, self-healing) |
| svc-boards | (locked)          | display renderer service identity (shell finding) |

## Facts the scoring depends on

- **Guessing ledger:** 4 ssh failures then 1 accepted password
  (`85-skylark-replay.py`, `attempts = [...]`) — the forensics answer
  `fq-guess-count` and the unit test both pin `4`.
- **Skylark's address** `203.0.113.44` (RFC 5737) appears in: the ssh
  journal, root's `authorized_keys` comment, the iptables backdoor rule,
  `/etc/hosts`, and the bashrc filter.
- The portal footer credits **Skylark Field Services** — the on-box
  breadcrumb for the contractor-name forensics; it must stay out of the
  handbook.
- First boot may hold the dpkg lock ~4 min (unattended-upgrades, Broadneck
  lesson) — wait, don't force.
