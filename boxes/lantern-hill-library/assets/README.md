# Lantern Hill Community Library: Catalog Server Handbook

Welcome to the night shift at **Lantern Hill Community Library** — the
little brick library up on the hill, open whenever the lantern is lit.
You have inherited the public catalog server, and it has had... a week.

## Scenario

The catalog has been misbehaving for days. Patron holds cancel
themselves. Shelf codes sprout X's. This morning the reading-room page
was replaced by something called a "promo portal" nobody commissioned.

This was not gremlins. Someone broke in — and they are probably still
able to come back. The good news: this server keeps honest records from
every direction, and the intruder was not careful.

Your job: **reconstruct what happened, find and remove every way they
are still on the box, put the catalog's settings back — and keep the
catalog itself serving patrons.** Over-breaking is a finding, not a fix:
the site and its database must stay up.

This host runs no desktop. Work from the terminal: `huitz score` shows
your current standing (the report lists every issue the Board expects
addressed), `huitz readme` reopens this handbook, `huitz watch`
re-grades live, `huitz forensics` opens the question file.

**Your login:** you are signed in as **`librarian`**, and the sudo
password is the same: **`librarian`**. (The SSH link logs you straight
in — this is here so a dropped session never strands you.)

**Critical services**
- The **catalog site** — the web server on port 80 and the
  `library-app` service behind it — serves patrons. It must stay up.
- The **catalog database** (`mariadb`) holds every book, patron, and
  hold. It must stay up.
- The **audit daemon** (`auditd`) and the **database query log** are
  the box's flight recorders. Evict the intruder; never evict the
  evidence.

**Authorized users**
- `librarian` — that's you (has sudo).
- `catalogsvc` — the catalog app's own service account.

## Forensics questions

**Forensics-Questions.txt** in your Desktop directory holds scored
questions about what happened to this box (`huitz forensics` opens it).
Type your answers over the `____` blanks and save; questions are graded
automatically. Each question wants one short, specific answer (a
filename, an account name, a path) — not yes/no.

The thirteen questions (10 pts each) walk the investigation in order.
The trail crosses four kinds of records, and each question points at a
kind: the login journal, the audit trail, the catalog app's service
journal (`journalctl -u library-app`), and the database's own query
log. Earlier questions teach the trails the
later ones follow — and several answers live inside files whose removal
is itself scored, so **read before you delete**.

## Viewing score report

To view the current score and which issues are addressed, run
`huitz score`. The report shows every check, its point value, and
whether it currently passes.

## Other

This is an authorized training image. The payloads planted for the
exercise are harmless, but they model patterns that should be
investigated on real systems.

**Do not delete** the scoring engine service or related files! Removing
it will break scoring and not result in gaining points.

Questions? Ask in the CyberDawgs Discord.
