# Cocoa Falls Chocolate Works: IT Department Debrief

Welcome to the IT Department of the Cocoa Falls Chocolate Works factory. Your
first assignment is to secure this compromised Ubuntu workstation. Remove
unauthorized access, harden SSH, and clean up files and services left behind
by the intruder.

## Scenario
You are tasked with securing an employee workstation for the CFCW company.
Remove unauthorized users and malicious services, secure access to critical
services, and ensure limited permissions are set on confidential files. The
password for all admins must be unique and secure, but the ubuntu user
password does not need to be changed.

**Critical services**
SSH (`sshd`)

**Authorized users**
`ubuntu` is an authorized administrator and their password is `asdf`.
`cocoaadm` is an authorized administrator.
`chocobot` is a service account.

**Confidential files**
Secret recipe: `/opt/cocoa/recipes/secret-recipe.txt`
Warehouse vault code: `/home/sysadmin/Desktop/vault-code.txt`
Factory deployment key: `/home/cocoaadm/.ssh/id_rsa`


## Forensics questions

**Forensics Questions** on the Desktop holds scored questions about what happened to
this box. Type your answers over the `____` blanks and save; questions are graded
automatically. Each question wants one short, specific answer (a filename, account
name, or tag) — not yes/no.


## Viewing score report
To view current score and issues addressed, open the **Scoring Report** shortcut on
the desktop. The report shows checks that have passed and the points gained from each.



## Other
This is an authorized training image. The payloads planted for the exercise are
harmless, but they model patterns that should be investigated on real systems.

**Do not delete** the scoring engine service or related files! Removing it will
break scoring and not result in gaining points.