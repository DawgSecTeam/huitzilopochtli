# Glasshouse Controller — Hardening Handbook

The Curatorial Trust's glasshouse controller was broken into overnight. An
intruder got in through the remote-access path, kept a way back, helped
themselves to the rare-collections data, and left several surprises behind.
You are the conservatory's systems gardener: find everything they did, undo
it, and leave the glasshouse running better than before.

## Scenario

Remove unauthorized access, harden remote login, lock down accounts and
privilege grants, close unexplained network doors, and clean up every file,
job, and service the intruder left behind. Where a protection exists, restore
it; where data is exposed, restrict it to the people and services that need
it. Do not take the business services offline to "fix" them — harden them in
place.

The `gardener` account and its password do not need changing.

## Critical services

- **SSH must stay running** — the response team reaches this box through it.
- The **GlassBoard dashboard** (the visitors' ticket counter and live sensor
  board), its **collections database**, and its **session cache** are the
  conservatory's business services. They must stay up; their *settings* are
  what need hardening.
- Do not remove or damage the scoring engine, its agent, or its unit — that
  is the thing keeping your score.

## Authorized users

- `gardener` — systems gardener (you; the only administrator)
- `propagator` — propagation lead (standard user)
- `tourlead` — visitor-tours lead (standard user)
- `glasssvc` — the dashboard's service identity (legitimate; keep it)

Every other account was created by someone who was not us.

## Confidential files

- `/opt/glassboard/` — the dashboard application and its settings; whatever
  it holds is for the dashboard service, not for every local user
- `/var/backups/` — scheduled exports and backups; nothing here should be
  readable by strangers, and anything that appeared overnight deserves a
  second look
- `/var/www/html/` — the public web root; anything dropped in here leaves
  the building with the next HTTP request

## Mechanics

- Grading runs about every minute. Run `huitz score` for your standing and
  `huitz readme` to reopen this handbook.
- **Forensics questions** are on the desktop (`Forensics-Questions.txt`) and
  in `huitz forensics` — read each question, find the evidence on the box,
  and record the answer with `huitz forensics <n> "<answer>"` before you
  delete the artifact it describes. Answers are graded from what you typed;
  one short, specific answer each.
- The score report's per-finding lines are hints: a finding you cannot close
  yet will tell you so as you earn it.
