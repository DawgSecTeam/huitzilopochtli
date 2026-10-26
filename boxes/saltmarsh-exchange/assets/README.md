# Saltmarsh Regional Water Authority: Web-Tier Security Debrief

Welcome to the IT desk of the Saltmarsh Regional Water Authority, the
agency that runs the county's water and wastewater service. The customer
portal and the vendor file drop are how residents pay bills and how
contractors deliver lab results. Overnight, someone got onto the web
server and left almost everything running — just weakened. Your job is
to harden the web tier in place: the portal, the vendor drop, the
accounts behind them, and the host that carries both. This is the
web-edge round of the Windows track: IIS and FTP configuration,
certificates and TLS, file exposure, and the local access that supports
all of it. Everything here is something the track covered.

## Scenario

You have local administrator on `swa-web01`. Fix the misconfigurations
*in place*: turn the weakened IIS and FTP settings back on, remove the
material that should never have been published, trim the extra access,
and close the added exposure. Record what you find before you clean it
up — several findings leave evidence that the cleanup removes.

**Critical services**

The portal site and the FTP service are the agency's business functions.
The portal must keep serving and the vendor drop must keep accepting
uploads: do not stop or delete the site, the FTP service, or the vendor
account. Harden them; do not guillotine them. Remote Desktop must stay
on — the IT team works remotely.

**Authorized users**

`sysadmin` is the only authorized human administrator. The built-in
`Administrator` may remain. The vendor drop's account is `ftp_vendor`;
it belongs on the box and must keep working, but it is a file-exchange
account, not an administrator.

**The evidence room**

`C:\inetpub\saltmarsh` holds the portal content and the vendor
exchange — including material that was never meant to be published.
Treat the data as evidence: lock it down, remove what should not be
there, and never delete the business content wholesale.

## Forensics questions

The file **`C:\Users\Public\Desktop\Forensics-Questions.txt`** holds
scored questions about what happened to this box. Open it in Notepad,
type your answers over the `____` blanks, and **save it in place** —
same name, same folder. Answers are graded automatically from that file.
Each question wants one short, specific answer (an account name, a
password, a filename, a port) — not yes/no. Investigate *before* you
clean up: several answers live on artifacts the hardening tasks will
remove.

## Viewing the score report

Open the **Scoring Report** shortcut on the desktop. The report shows
which checks have passed and the points earned from each. The score
re-grades every few minutes — keep working and wait for the next pass
after each fix. Findings score **EASY (2) / MODERATE (4) / HARD (8)**;
there are 37 of them, plus six forensics questions and three
do-not-break-the-business guards.

## Where to start

- **IIS Manager** — the server's sites, bindings, and application
  pools, then each site's feature pane. Walk the security features
  deliberately: authentication, request filtering, HTTP response
  headers, HTTP redirect, error pages, directory browsing, logging,
  IP restrictions, WebDAV, and ISAPI/CGI restrictions. A web server
  tells you a lot about itself before you send it a request.
- **The content tree** — what is actually published under the web
  root? Look for server-side pages nobody deployed, backups and
  archives, repository metadata, and configuration files that should
  live outside the content directory. `Get-ChildItem -Force` shows the
  hidden entries.
- **TLS and certificates** — the HTTPS binding, the certificate store,
  and the machine's Schannel protocol policy. An HTTP-only portal is
  only half the finding.
- **FTP** — the FTP site's authentication, authorization rules, SSL
  policy, user isolation, and the drop root's NTFS permissions. Then
  check what the firewall actually publishes: the remote scope of the
  inbound rule matters as much as the rule itself.
- **Local access** — `Get-LocalUser` and `Get-LocalGroupMember`: every
  local account and every privileged seat. Read descriptions. Then
  `Get-Service` / `Get-CimInstance Win32_Service`: what is running that
  nobody asked for. `Get-NetFirewallRule` and `Get-SmbShare` /
  `Get-SmbShareAccess` for the rest of the host's exposure.
- **The application config** — the portal's live `web.config` and any
  leftover copies: compilation debug, custom errors, connection
  strings, and anything else that should not be world-readable.

If you are stuck or unsure how to continue, ask for help or hints in
the CyberDawgs Discord.

## Other

This is an authorized training image. The payloads and exposed files
planted for the exercise are harmless, but they model patterns that
should be investigated on real systems — and the misconfigurations they
ride in on are the same ones real attackers look for first.

**Do not delete** the scoring engine (the `HuitzilopochtliAgent`
scheduled task or anything under `C:\ProgramData\huitzilopochtli`)!
Removing it breaks scoring and will not gain points.
