# Cinder Ridge Credit Union: Branch Workstation Debrief

Welcome to the Cinder Ridge Credit Union incident response. A teller
workstation was compromised after a fake member-statement update. The
intruder established persistence in the registry and weakened several
baseline controls. Your job is to find and remove the persistence, restore
the controls, and answer the forensics questions before you clean up.

## Scenario

You are securing `cr-teller01`, a Windows workstation used at the Cinder
Ridge branch. The branch's teller operations must remain usable:

- Remote Desktop must stay ON. Do not disable the network adapter or the
  RDP listener, and do not lock yourself out.
- Do not change the `sysadmin` password or disable that account; the
  remote-access link depends on it.
- The standard teller account must stay enabled. It is not an
  administrator.
- The scoring agent must stay installed.

Remove the attacker's registry persistence, restore the weakened platform
controls, and leave the legitimate vendor services working. Some changes
take effect at the next reboot; record evidence before you reboot or
delete anything.

**Authorized administrator:** `sysadmin`. No other account should be in the
local Administrators group. (The built-in `Administrator` account may remain
a member.)

## Forensics questions

`Forensics-Questions.txt` on the Desktop contains six scored questions.
Type each answer over the `____` blank and save the file. Answers are short
and specific -- an account name, a service name, a value name, or a path.
Investigate and record evidence BEFORE you remove the artifacts: some
answers live on the persistence you are about to delete.

## Viewing the score report

Open the **Scoring Report** shortcut on the Desktop. The report lists the
checks that pass and the points earned. The agent re-grades every few
minutes; wait for the next pass after a change.

## Where to start

This box is about the Windows registry. Learn to read it before you change
it: `regedit` is the GUI, and `reg query` / `Get-ItemProperty` are the
command-line views. Save a copy of a key before editing it (`reg export`)
so you can compare the before and after states.

- **Autoruns at logon.** The classic Run and RunOnce keys exist per machine
  and per user. Windows also honors policy Run keys, and the 32-bit view of
  the machine keys lives under `WOW6432Node`. Query the key, read each value
  name and its command, and check both hives.
- **Per-user hives.** A logged-in user's settings are under
  `HKEY_USERS\<SID>`; an offline user's hive is `C:\Users\<name>\NTUSER.DAT`.
  `regedit` can load an offline hive with File > Load Hive. Do not assume
  the administrator's HKCU is the only user hive on the box.
- **Services.** `HKLM\SYSTEM\CurrentControlSet\Services` holds each
  service's `ImagePath`, and recovery actions can store a `FailureCommand`.
  Compare what the registry says with what the service actually runs.
- **Logon hooks.** Winlogon's `Userinit` and `Shell` values run at
  interactive logon. Review them for unexpected additions.
- **Baseline controls.** Check UAC (`EnableLUA`), Defender policy and
  real-time status, WDigest (`UseLogonCredential`), LSA protection
  (`RunAsPPL`), SMB1, and AlwaysInstallElevated in both HKLM and the
  user's hive.
- **Standard tools.** `regedit`, `reg query`, `reg export`,
  `Get-ItemProperty`, `Get-ChildItem`, `services.msc`, and `lusrmgr.msc`.

If you're stuck or unsure how to continue, ask for help or hints in the
CyberDawgs Discord.

## Other

This is an authorized training image. The planted payloads are harmless,
but they model patterns worth investigating on real systems.

**Do not delete** the scoring engine (the `HuitzilopochtliAgent` scheduled
task or anything under `C:\ProgramData\huitzilopochtli`). Removing it breaks
scoring and earns no points.
