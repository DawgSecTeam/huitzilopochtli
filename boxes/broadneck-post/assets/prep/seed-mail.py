#!/usr/bin/env python3
"""Broadneck Post template prep -- seeded depot mail.

Writes a few months of mundane, non-plot Maildir messages for the four
depot accounts. Deliberately boring: this is the cover traffic that makes
the mailboxes real, NOT evidence -- none of it may mention the intruder,
the lure domain, or any planted artifact name (forensics answers!).
Runs BEFORE the replay, so the boxes are warm when redtag arrives.
"""
import os
import time

USERS = ["dispatch", "routes", "freight", "postmaster"]
HOST = "broadneck-mailer"

# (owner, From, To, Subject, body) -- dates fixed in the past on purpose:
# the depot's mail predates the incident by weeks.
MAIL = [
    ("dispatch", "routes@broadneckpost.org", "dispatch@broadneckpost.org",
     "Route 12 slip corrections",
     "Morning,\n\nSlips 1188-1201 were keyed to the wrong loop after the\n"
     "depot re-map. Corrected copies are in the blue tray; please re-sort\n"
     "before the 09:40 pull.\n\n-- Route Coordination\n"),
    ("dispatch", "freight@broadneckpost.org", "dispatch@broadneckpost.org",
     "Dock door schedule change (week 43)",
     "Dock 3 is down for a door-motor swap Tuesday. Bulk drops move to\n"
     "dock 5 for that day only. Parcel flow stays normal.\n\n-- Freight Desk\n"),
    ("routes", "postmaster@broadneckpost.org", "routes@broadneckpost.org",
     "October route audits -- due date",
     "All October route audits are due by the last Friday of the month.\n"
     "Use the yellow forms, not the green ones; the green form still has\n"
     "last year's zone map on the back.\n\n-- Postmaster\n"),
    ("routes", "dispatch@broadneckpost.org", "routes@broadneckpost.org",
     "Union meeting minutes -- September",
     "Minutes are posted on the break-room board. Highlights: overtime\n"
     "sign-up is digital now, and the holiday sort schedule is unchanged\n"
     "from last year.\n\n-- Dispatch Desk\n"),
    ("freight", "dispatch@broadneckpost.org", "freight@broadneckpost.org",
     "Customs paperwork backlog",
     "Eleven international parcels are waiting on customs forms (the\n"
     "senders under-declared). Flagged the bins; they go out as soon as\n"
     "the forms come back.\n\n-- Dispatch Desk\n"),
    ("freight", "postmaster@broadneckpost.org", "freight@broadneckpost.org",
     "Pallet scanner firmware update window",
     "IT will push the scanner firmware Sunday 06:00-07:00. Scanners must\n"
     "be on chargers. Nothing else changes -- barcode formats are the\n"
     "same.\n\n-- Postmaster\n"),
    ("postmaster", "root@broadneckpost.org", "postmaster@broadneckpost.org",
     "Monthly mail queue health report",
     "Queue volume: nominal. Deferred spikes: none. Disk: 61% used.\n"
     "Reminder: the relay config is the contractor's; treat any change\n"
     "requests with suspicion.\n\n-- cron\n"),
    ("postmaster", "freight@broadneckpost.org", "postmaster@broadneckpost.org",
     "Vendor renewal: stamp supplies",
     "The stamp vendor contract renews next month. Their invoices come\n"
     "through the mail room; forwarding the renewal quote for your\n"
     "sign-off.\n\n-- Freight Desk\n"),
]


def write_maildir(user, msg, ts):
    base = f"/home/{user}/Maildir"
    for sub in ("new", "cur", "tmp"):
        os.makedirs(f"{base}/{sub}", mode=0o755, exist_ok=True)
    name = f"{int(ts)}.M{int(ts % 1_000_000)}P{os.getpid()}.{HOST}"
    path = f"{base}/new/{name}"
    with open(path, "w") as f:
        f.write(msg)
    os.chmod(path, 0o600)
    uid = os.stat(f"/home/{user}").st_uid
    gid = os.stat(f"/home/{user}").st_gid
    for root, dirs, files in os.walk(base):
        os.chown(root, uid, gid)
        for n in dirs + files:
            os.chown(os.path.join(root, n), uid, gid)


# Spread the messages across the weeks BEFORE the incident date.
start = time.time() - (28 * 86400)
for i, (owner, frm, to, subj, body) in enumerate(MAIL):
    ts = start + i * (3 * 86400)
    date = time.strftime("%a, %d %b %Y %H:%M:%S -0400", time.gmtime(ts))
    msg = (
        f"From: {frm}\n"
        f"To: {to}\n"
        f"Subject: {subj}\n"
        f"Date: {date}\n"
        f"Message-Id: <seed-{i}@broadneckpost.org>\n"
        f"\n{body}"
    )
    write_maildir(owner, msg, ts)
    print(f"seed-mail: {owner} <- {subj!r}")

print(f"seed-mail: {len(MAIL)} messages across {len(USERS)} mailboxes")
