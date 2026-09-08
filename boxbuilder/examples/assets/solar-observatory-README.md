# Coyolxauhqui Ridge Solar Observatory: IT Department Debrief

Welcome to the IT Department of the Coyolxauhqui Ridge Solar Observatory. Your
first assignment is to secure this compromised Ubuntu workstation. Remove
unauthorized access, harden SSH, and clean up files and services left behind
by the intruder.

## Scenario
You are tasked with securing an observatory control workstation for the CRSO
facility. Remove unauthorized users and malicious services, secure access to
critical services, and ensure limited permissions are set on confidential
files. The password for all admins must be unique and secure.

**Critical services**
SSH (`sshd`) and the public status site (`apache2`) must stay running.

**Authorized users**
`obsadmin` is the only authorized administrator.
`heliobot` is a service account.

**Confidential files**
Telescope control keys: `/opt/observatory/telescope-keys.txt`
Observatory deployment key: `/home/obsadmin/.ssh/id_rsa`


## Forensics questions

**Forensics Questions** on the Desktop holds scored questions about what happened to
this box. Type your answers over the `____` blanks and save; questions are graded
automatically. Each question wants one short, specific answer (a filename, account
name, port, or tag) — not yes/no.


## Viewing score report
To view current score and issues addressed, open the **Scoring Report** shortcut on
the desktop. The report shows checks that have passed and the points gained from each.



## Other
This is an authorized training image. The payloads planted for the exercise are
harmless, but they model patterns that should be investigated on real systems.

**Do not delete** the scoring engine service or related files! Removing it will
break scoring and not result in gaining points.
