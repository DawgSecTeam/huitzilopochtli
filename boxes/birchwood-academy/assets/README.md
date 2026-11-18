# Birchwood Academy — School Records & Homework Portal Server

You are the technology team for Birchwood Academy, a small private
school. The machine in front of you is the school's only server: it
hosts the homework portal students and parents reach from the network,
it stores the student records archive the front office shares, and the
office connects to it remotely during the school day. Last week a staff
member opened an email about "grade corrections" that was not about
grade corrections. Since then the portal has had hiccups, the
attendance software has complained about accounts it never created, and
a vendor nobody can reach by phone apparently has a support login.

Remove the intruder's access and every way back in, harden this server
the way a school that keeps student records should, and keep the
school's services running while you do it.

## Scenario

- Audit every account against the roster below. The intruder created
  their own — and gave at least one more privilege than any student or
  vendor should ever have here. Disable what should be disabled; remove
  what was never legitimate.
- Hunt persistence: there are several independent ways back onto this
  machine, and at least one of them rebuilds the others when you remove
  them piecemeal.
- The remote-access tools planted on this box duplicate access the
  school never sanctioned; the sanctioned remote desktop path stays,
  but it must require the protection it is missing.
- File sharing is how the front office works — but the way the records
  archive is shared today, "everyone" is not a figure of speech, and
  the legacy protocol underneath it should have retired a decade ago.
- An anonymous caller should not be able to list this server's accounts
  and shares; credential hygiene (logon protection, stored cleartext
  passwords, account flags) needs attention; and the protective
  software and logging that would have made this incident visible were
  switched off before the intruder arrived.
- The portal itself is serving something it never should have been.

The `registrar` password does not need to be changed, and the `frontdesk`
password stays as it is until the office manager says otherwise — the
intruder already had both; the fixes below are what lock them out.

## Critical services

Do not stop or uninstall these — the school day depends on them, and
breaking them costs points: the web server publishing the homework
portal, the file sharing service behind the records archive, and the
remote desktop service the office connects with.

## Authorized users

- **registrar** — school registrar (your account; administrator)
- **frontdesk** — the attendance-window account (standard user)
- **svc-attendance** — the attendance-sync service identity (it exists
  to run one job, not to log in; its password settings, not its
  existence, are the problem)

Any other account able to log in is unauthorized — including any
"vendor support" identity nobody at the school can name a contract for,
and any student account with more reach than a classroom workstation.

## Confidential files

- The student records archive under `C:\Shares\`. Student data lives
  here; share it with the office, not with everyone.
- The homework portal's web root. It faces the whole school network;
  only the portal belongs there.
- The gradebook integration's data folder under ProgramData. It should
  hold configuration, not copies of student records.

## Mechanics

- Run `huitz score` at any time for your standing; the report names
  each finding as it is earned or lost.
- Forensics questions are graded from `Forensics-Questions.txt` on the
  desktop: record short, specific answers with `huitz forensics <n>
  "<answer>"`. Read the box, then answer.
- Do not delete, stop, or modify the scoring engine or anything under
  `C:\ProgramData\huitzilopochtli`. It is the grader, not an intruder
  artifact.

Good hunting — fifth period starts in ten minutes.
