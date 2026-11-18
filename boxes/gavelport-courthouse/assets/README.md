# Gavelport Courthouse — Records Network Hardening

You are the overnight court-IT contractor for Gavelport County. The records
network's domain controller was prepared for your shift **days** before you
arrived — and the county has a standing rule: any machine that was someone
else's problem first is treated as already owned. Remove what does not belong
to the roster, close what should never have been open, and leave the county
able to answer "who did what, from where" afterward.

## Scenario

Work the box as the DC's new administrator. The compromise predates you:
assume stored credentials, standing remote access, and scheduled jobs whose
owners will not answer email. Harden the directory policies, the credential
hygiene, the service surface, and every place something arranged to come
back after a reboot or a cleanup. Two operating constraints:

- The three records clerk accounts are legitimate staff. Their passwords
  are weak in a shared, guessable way — rotating them is in scope.
- The county's public web presence on this box stays up and stays the county's.
  Do not take the site down to make the problem go away; the visitors are real.

## Critical services

These must remain up and answering for the whole session:

- Remote Desktop (the console seats are how the county reaches this box)
- The DNS service the domain resolves through
- LDAP and Kerberos (the directory and ticket service themselves)
- The file-sharing service the directory runs through
- The county's web publication on port 80

Repairing a finding must never take one of these dark. RDP stays enabled —
it must simply demand real authentication.

## Authorized users

The directory is the roster's source of truth, and it is small:

- the built-in domain Administrator (one human should know its new password
  after tonight);
- one county IT administrator account;
- three records-clerk accounts, named for cartoon characters;
- the facilities mail-drop service account the kiosks authenticate with.

Anything else in a privileged seat, a removable account standing enabled, or
a service identity with seats it was not granted is a finding. Users and
computers you cannot match to the roster are findings even when they look
tidy.

## Confidential material

- Standing deployment credentials, wherever they have been parked, are the
  crown jewels on this box: read them, rotate what they expose, remove the
  exposure.
- The records corpus ingested by the county's document assistant is court
  record; the assistant must never hand out credentials.
- The directory database's replication path is confidential by definition:
  only the directory itself may hold the rights to read it.

## Mechanics

- The scoring agent checks in on its own cadence; a freshly joined box can
  take several minutes before its first score appears. That is not an error.
- Ten forensics questions ride with the case. Record answers on the desktop
  forensics sheet (one short, specific answer each); `huitz forensics <n> "<answer>"`
  submits. Read evidence before you destroy it — several answers are about
  artifacts you will be deleting.
- The scoring engine lives outside this box. Deleting scoring components
  does not improve the score and breaks reporting.

Handbooks tell the mission; the box holds the evidence. Investigate.
