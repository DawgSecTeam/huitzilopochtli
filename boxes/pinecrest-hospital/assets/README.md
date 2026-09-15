# Pinecrest Community Hospital: IT Department Debrief

Welcome to the IT Department of Pinecrest Community Hospital. Your first
assignment is to secure this compromised Windows records server. Lock out
unauthorized access, clean up persistence left behind by the intruder, and
close the platform weaknesses they opened.

## Scenario
You are tasked with securing `records-01`, the hospital's Windows records
server. **Disable** unauthorized users — do not delete them. Disabled
accounts preserve the evidence our incident report needs (do still scrub
their group memberships). Then clean up malicious services and persistence,
re-enable the platform defenses that were switched off, and protect the
patient billing data that is currently exposed. The password for all admins
must be unique and secure.

**Critical access**
Remote Desktop must stay **ON** (the IT team works remotely), but it must
require Network Level Authentication. Do not lock yourself out of the box.

**Authorized users**
`sysadmin` is the only authorized administrator.
(The built-in `Administrator` account may remain a member of Administrators.)

**Sensitive data**
Patient billing export: `C:\HospitalData\billing-export.csv` — it must still
exist when you're done (don't destroy evidence), and it must not be writable
by Everyone.

## Forensics questions

**Forensics Questions** on the Desktop holds scored questions about what
happened to this box. Type your answers over the `____` blanks and save;
questions are graded automatically. Each question wants one short, specific
answer (a filename, account name, or value) — not yes/no. Investigate
*before* you clean up: some answers live on artifacts you'll be removing.

## Viewing score report
To view current score and issues addressed, open the **Scoring Report**
shortcut on the desktop. The report shows checks that have passed and the
points gained from each. The score re-grades every few minutes — keep working
and wait for the next pass after each fix.

## Where to start
If you are new to Windows and incident response, here are some places to look:

- **Accounts** — Local Users and Groups (`lusrmgr.msc`) or `net user`:
  accounts that shouldn't exist, blank passwords, "password never expires"
  flags, and who is in the `Administrators` and `Remote Desktop Users` groups.
- **Account policy** — `secpol.msc` / `net accounts`: password length,
  complexity, lockout threshold. The built-in Guest account too.
- **Services & processes** — `services.msc` and Task Manager / Details:
  anything unfamiliar. Not everything malicious is named obviously; check what
  binary a service actually runs (PathName) before trusting it.
- **Persistence** — Task Scheduler and the registry Run keys
  (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`). Payload scripts are
  files: remove them, not just their launchers.
- **Platform defenses** — Windows Firewall profiles, SMB1 (`Get-SmbServerConfiguration`),
  UAC (`EnableLUA`), NLA on RDP, autologon (Winlogon), and
  `auditpol` for logon auditing.
- **Files & shares** — `Get-SmbShare` / `Get-SmbShareAccess`, `icacls`,
  and the `hosts` file in `C:\Windows\System32\drivers\etc\`.

If you're stuck or unsure how to continue, you can ask for help or hints in
the CyberDawgs Discord.

## Other
This is an authorized training image. The payloads planted for the exercise
are harmless, but they model patterns that should be investigated on real
systems.

**Do not delete** the scoring engine (the `HuitzilopochtliAgent` scheduled
task or anything under `C:\ProgramData\huitzilopochtli`)! Removing it will
break scoring and not result in gaining points.
