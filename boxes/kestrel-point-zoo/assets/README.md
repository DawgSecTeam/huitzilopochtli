# Kestrel Point Operations Server — Hardening Handbook

Someone broke into the park's operations server overnight. The wildlife-
trafficking ring that has been circling Kestrel Point got in, kept a way
back, weakened every guard the server had, and left things behind that will
come back if you miss them. You are the park's systems keeper: find
everything they did, undo it, and leave the park running.

## Scenario

Remove unauthorized access, restore the protection stack, tighten accounts
and authentication, close every unexplained door, and clean up the
persistence they planted. Where a business service is misconfigured, harden
it in place — do not take it offline to "fix" it.

The `sysadmin` account and its password do not need changing. Disabling an
unauthorized account scores; deleting it does not (and destroys evidence) —
unless its own task explicitly says otherwise.

## Critical services

- **Remote Desktop must stay running** — the response team reaches this box
  through it.
- The **ticketing portal** (IIS) and the **keeper data share** are the park's
  business functions. They must stay up; their *configuration* is what needs
  hardening.
- Do not remove or damage the scoring engine, its agent, or its task — that
  is the thing keeping your score.

## Authorized users

- `sysadmin` — the operations/IT account (you)
- `Administrator` — the built-in account (authorized, on the roster)

Every other local account was created by someone who was not us. The
keepers' devices reach their share over the network, not by local accounts.

## Confidential files

- `C:\KeeperData\` — the keeper tablets' drop, including the outgoing folder
  staged for vendor deliveries; whatever sits here should be readable only
  by the accounts that need it
- The **ticketing portal's web root** — anything dropped in there leaves the
  building with the next HTTP request
- `C:\ProgramData\` — service and application data; read what a "helper"
  actually contains before you trust its name

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
