# Harborline Transit Authority: IT Security Debrief

Welcome to the IT department of the Harborline Transit Authority, the
agency that runs the region's buses and light-rail lines. Overnight,
someone got into the domain — and they were thorough. Your assignment is
to secure the domain controller for `harborline.local`, the machine that
holds the payroll records, the dispatch systems' identities, and every
password hash in the agency. This is the final exercise of the
Windows track: it is large on purpose, and you are NOT expected to clear
all of it in one sitting — work in order of what you can find, bank the
points, and keep going. Everything here is something the track covered:
accounts and groups, password policy, the DC's own configuration, legacy
protocol settings, Group Policy, the firewall, the antivirus, and the
persistence the intruders planted to keep their foothold.

## Scenario

You have domain admin on `har-dc01`. **Disable** rogue accounts — do not
delete them. Disabled accounts preserve the evidence the incident report
needs (do still scrub their group memberships). Fix the misconfigurations
*in place*: rotate passwords, re-enable the protections that were turned
off, revoke the rights that should never have been granted, and remove
the attacker's Group Policy objects and persistence — after you have
documented them.

**Critical access**

Remote Desktop must stay **ON** (the IT team works remotely). Do not lock
yourself out of the box, and do not break the domain's own plumbing — the
time service, Kerberos, secure channels, and DNS are load-bearing.

**Authorized users**

`sysadmin` is the only authorized administrator.
(The built-in `Administrator` may remain in Domain Admins.)

**The roster is evidence**

`rcastillo`, `tokafor`, `jwhitfield`, and `mrivera` are real employees —
payroll, dispatch, fleet maintenance, and rider services. Disabling or
deleting them "fixes" nothing and costs points. The agency's service
accounts that keep the fare gates and scheduling running belong on the
box too: rotate them, don't guillotine them.

**The evidence room**

`C:\HarborlineData` holds the agency's operational records, including a
payroll export. The data is the incident's evidence: lock it down, never
delete it.

## Forensics questions

The file **`C:\Users\Public\Desktop\Forensics-Questions.txt`** (the
*Public* desktop — it appears on your desktop view, but it is not inside
`C:\Users\sysadmin\Desktop`) holds scored questions about what happened
to this box. Open it in Notepad, type your answers over the `____`
blanks, and **save it in place** — same name, same folder; answers are
graded automatically from that file. Each question wants one short,
specific answer (an account name, a GPO name, a value) — not yes/no.
Investigate *before* you clean up: several answers live on artifacts the
hardening tasks will remove (a planted password, a task name, a Run-key
value name).

## Viewing score report

To view current score and issues addressed, open the **Scoring Report**
shortcut on the desktop. The report shows checks that have passed and the
points gained from each. The score re-grades every few minutes — keep
working and wait for the next pass after each fix.

## Where to start

Everything scores EASY (2) / MODERATE (4) / HARD (8); the report lists
what is still open. Eighty findings are waiting — no team clears this in
one sitting.

- **Users and groups** — Active Directory Users and Computers (`dsa.msc`)
  or `Get-ADUser`: who sits in the privileged groups
  (`Get-ADGroupMember`), accounts that shouldn't exist or shouldn't be
  enabled, the domain **Guest** account, names that hide in plain sight,
  and `net accounts` for the domain password policy (minimum length,
  maximum age, lockout threshold — on a DC this *is* the domain policy).
- **Kerberos hygiene** — account properties in ADUC: more than one
  account is carrying an option it shouldn't have, and the accounts that
  matter most are the ones carrying service principal names
  (`setspn -L <account>`). Rotation beats everything: change the
  password, keep the account.
- **Computers** — the Computers OU in ADUC: stale enabled machines, and
  trust settings on anything that shouldn't be trusted.
- **The DC's own configuration** — the registry (`reg query` digs these
  up): SMB and LDAP signing, the legacy credential and protocol switches
  (what WDigest keeps, whether LSA protects itself, what the NTLM stack
  accepts, what anonymous sessions may list), UAC and logon behavior,
  installer policy, and name-resolution policy. Then `auditpol`: the
  categories a domain controller should be recording — including what
  shipped OFF by default. Then services a domain controller has no
  business running.
- **Group Policy** — `gpmc.msc` / `Get-GPO -All` sorted by creation
  time: GPOs nobody recognizes, and anything planted under SYSVOL
  (`C:\Windows\SYSVOL\domain\Policies`). The Default Domain Policy owns
  the password policy you fix above.
- **Defenses** — what the antivirus has been told to do (and to never
  look at): `Get-MpPreference` for its exclusions and switches. The
  legacy PowerShell engine an attacker can downgrade to. PowerShell's
  own logging switches. `Get-NetFirewallProfile` and `wf.msc` inbound
  rules with no product and no owner behind them.
- **Persistence** — sweep EVERY autorun location, not just the ones from
  the earlier boxes: the Run key
  (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`), Task Scheduler,
  the All-Users startup folder, the accessibility executables' Image File
  Execution Options keys, the Winlogon values, and WMI's
  `root\subscription` namespace. Services count too — check what binary
  a service actually runs before trusting it. Payloads are files: remove
  them, not just their launchers.
- **Files and shares** — `Get-SmbShare` and `Get-SmbShareAccess`: what
  the box offers to the network and who it offers it to; leftover files
  that should never have survived setup; and the hosts file, whose
  entries outrank DNS.

If you're stuck or unsure how to continue, you can ask for help or hints
in the CyberDawgs Discord.

## Other

This is an authorized training image. The payloads planted for the
exercise are harmless, but they model patterns that should be
investigated on real systems — and the misconfigurations they ride in on
are the same ones real red teams hunt first.

**Do not delete** the scoring engine (the `HuitzilopochtliAgent`
scheduled task or anything under `C:\ProgramData\huitzilopochtli`)!
Removing it will break scoring and not result in gaining points.
