# Static Pine Community Radio: Transmitter Host Handbook

Welcome to the engineer's chair at **Static Pine Community Radio**, 88.3 FM —
the little low-power station up the pine ridge. Or rather, welcome to the
chair your predecessor abandoned mid-shift.

## Scenario

For weeks, somebody has been hijacking the overnight hours with a pirate
broadcast. Staff pull the plug every morning. Every night, it comes back.
Fuses pulled, antennas disconnected, one whole transmitter swapped — *it
still comes back.*

That is not a transmitter problem. The intruder wired their show into this
automation box everywhere it can start something on a schedule or at boot.
Your job: **find and remove every way the pirate broadcast comes back —
without breaking the station's own machinery.** Over-breaking is a finding,
not a fix.

This host runs no desktop. Work from the terminal: `huitz score` shows your
current standing, `huitz readme` reopens this handbook, `huitz watch`
re-grades live.

**Your login:** you are signed in as **`stationlead`**, and the sudo password
is the same: **`stationlead`**. (The SSH link logs you straight in — this is
here so a dropped session never strands you.)

**Critical services**
- The **cron daemon** (`cron`) and the **at daemon** (`atd`) run the
  station's own chores. They must stay up — evict the intruder's jobs, keep
  the daemons.
- The **`tapeops`** account is legitimate transmitter automation. Keep it.

**Authorized users**
- `stationlead` — that's you (has sudo).
- `tapeops` — legitimate service account.

## Forensics questions

**Forensics-Questions.txt** on the Desktop holds scored questions about what
happened to this box (`huitz forensics` opens it). Type your answers over the
`____` blanks and save; questions are graded automatically. Each question
wants one short, specific answer (a path, account name, or tag) — not yes/no.
The answers are sitting in artifacts you will open while hunting, so read
before you delete.

## Viewing score report

To view your current standing, run `huitz score` or open the **Scoring
Report** shortcut on the desktop.

## Other

This is an authorized training image. The payloads planted for the exercise
are harmless, but they model patterns that should be investigated on real
systems.

**Do not delete** the scoring engine service or related files! Removing it
will break scoring and not result in gaining points.

Questions? Ask in the CyberDawgs Discord.
