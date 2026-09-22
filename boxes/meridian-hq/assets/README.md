# Meridian Logistics: IT Security Debrief

Welcome to the IT department of Meridian Logistics. Overnight, someone got
into the domain — and they did not leave quietly. Your assignment is to
secure `dc01`, the domain controller for `meridian.local`, before Monday's
audit. Everything the attackers abused is something your workshop covered:
domain accounts and groups, computer objects, the DC's own configuration,
Group Policy, the firewall, and the persistence they planted to keep their
foothold.

## Scenario

You have domain admin on `dc01`. **Disable** rogue accounts — do not delete
them. Disabled accounts preserve the evidence the incident report needs (do
still scrub their group memberships). Fix the misconfigurations *in place*:
rotate passwords, re-enable the flags that were turned off, revoke the rights
that should never have been granted, and remove the attacker's Group Policy
objects and persistence — after you have documented them.

**Critical access**

Remote Desktop must stay **ON** (the IT team works remotely). Do not lock
yourself out of the box.

**Authorized users**

`sysadmin` is the only authorized administrator.
(The built-in `Administrator` may remain in Domain Admins.)

**The roster is evidence**

`mchen` and the other staff accounts are real employees. Disabling or
deleting them "fixes" nothing and costs points — this one only ever
subtracts.

## Forensics questions

The file **`C:\Users\Public\Desktop\Forensics-Questions.txt`** (the *Public*
desktop — it appears on your desktop view, but it is not inside
`C:\Users\sysadmin\Desktop`) holds scored questions about what happened to
this box. Open it in Notepad, type your answers over the `____` blanks, and
**save it in place** — same name, same folder; answers are graded
automatically from that file. Each question wants one short, specific answer
(an account name, a GPO name, a value) — not yes/no. Investigate *before*
you clean up: some answers live on artifacts the hardening tasks will remove
(an encrypted password inside SYSVOL, a task name, a Run-key value name).

## Viewing score report

To view current score and issues addressed, open the **Scoring Report**
shortcut on the desktop. The report shows checks that have passed and the
points gained from each. The score re-grades every few minutes — keep working
and wait for the next pass after each fix.

## Where to start

Everything scores EASY (5) / MODERATE (10) / HARD (20); the report lists
what is still open.

- **Users** — Active Directory Users and Computers (`dsa.msc`) or
  `Get-ADUser`: who sits in **Domain Admins** (`Get-ADGroupMember`),
  accounts that shouldn't exist or shouldn't be there, the domain **Guest**
  account, and `net accounts` for the domain password policy (minimum
  length, lockout threshold — on a DC this *is* the domain policy).
- **Kerberos hygiene** — account properties in ADUC: "Do not require
  Kerberos preauthentication" (AS-REP roasting) and "Use Kerberos DES
  encryption types" (downgrade). `setspn -L <account>` shows who carries a
  service principal name — roastable. Rotation beats everything: change the
  password, keep the account.
- **Computers** — the Computers OU in ADUC: stale enabled machines, and the
  **Delegation** tab ("Trust this computer for delegation") on anything
  that shouldn't be trusted.
- **Domain controller** — `reg query` of
  `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters` (LDAP signing),
  `Set-SmbServerConfiguration -EnableSMB1Protocol $false`, the **Print
  Spooler** service (a DC has no business printing), `auditpol /get
  /subcategory:"Logon"`, and the domain root's ACL
  (`Get-Acl "AD:DC=meridian,DC=local"`) for replication rights that
  shouldn't exist.
- **Group Policy** — `gpmc.msc` / `Get-GPO -All` sorted by creation time:
  GPOs nobody recognizes, and anything under SYSVOL
  (`C:\Windows\SYSVOL\domain\Policies`) carrying a `cpassword` — the
  MS14-025 password-in-GPP finding. The Default Domain Policy owns the
  password policy you fix above.
- **Firewall** — `Get-NetFirewallProfile` (all three must be on) and
  `wf.msc` inbound rules with no product and no owner behind them.
- **Persistence** — Task Scheduler, the Run key
  (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`), services whose
  BinaryPathName is a PowerShell script, and the scripts they point at in
  `C:\ProgramData\Subsystems`. Payloads are files: remove them, not just
  their launchers.

If you're stuck or unsure how to continue, you can ask for help or hints in
the CyberDawgs Discord.

## Other

This is an authorized training image. The payloads planted for the exercise
are harmless, but they model patterns that should be investigated on real
systems — and the AD misconfigurations they ride in on are the same ones
real red teams hunt first.

**Do not delete** the scoring engine (the `HuitzilopochtliAgent` scheduled
task or anything under `C:\ProgramData\huitzilopochtli`)! Removing it will
break scoring and not result in gaining points.
