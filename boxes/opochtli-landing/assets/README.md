# Opochtli Landing Port Authority — IT Department Debrief

Welcome aboard. You are the new IT hire at the **Opochtli Landing Port
Authority**, the harbor gateway where the region's cargo comes and goes —
including the chocolate concentrate for Cocoa Falls Chocolate Works and the
telescope optics bound for Coyolxauhqui Ridge Solar Observatory. Both of those
organizations made the news recently for the *wrong* reasons, and both of them
ship through your docks.

An audit just found that this gateway host was already broken into. Your
predecessor left in a hurry. Everything the attackers touched is still here.

Your job: **harden this box before the next ship docks.**

> In production this port's perimeter runs on a dedicated firewall appliance
> (a pfSense box at the edge). Perimeters matter — but they do nothing for a
> laptop that phones home from inside. This exercise is about the *host*
> firewall: netfilter, the engine under Linux firewalls, and `ufw`, the tool
> that drives it.

## Critical services (keep these alive)

- **SSH** must stay running and reachable. The pilot house (harbor office,
  subnet `10.0.0.0/24`) needs it. A firewall that locks the office out is a
  finding, not a fix — never lock yourself out.
- The desktop must stay usable.

## Authorized users

- `harbormaster` — the admin account (password `harbormaster`; it does not
  need to be changed).
- `cranelift` — a crane-control **service account**. Service identities do
  not get interactive login shells.

Any other account you find is not ours.

## Confidential files

- `/opt/harbor/manifests/master-manifest.txt` — cargo manifests. Restricted.
- `/home/harbormaster/.ssh/id_rsa` — the pilot's deployment key.

## Scoring

- The **Scoring Report** shortcut on the Desktop opens the live score report.
  It refreshes automatically every few minutes.
- **Forensics questions** are in `Forensics-Questions.txt` on the Desktop.
  Type your answers over the `____` blanks. Answers are re-graded
  automatically; wrong answers cost nothing, so always guess.
- Checks are **weighted by difficulty** (EASY 5 / MODERATE 10 / HARD 20) —
  the report shows the point value of each finding.
- Do **not** delete or tamper with the scoring agent.

## Where to start

Tools worth knowing (all in the workshop cheatsheet and the talk):

- `man ufw` — the simple front end. `ufw enable`, `ufw default deny incoming`,
  `ufw limit OpenSSH`, `ufw allow from 10.0.0.0/24 to any port 22`.
- `sudo iptables-save` and `sudo iptables -S` — read the ACTUAL ruleset.
  Files lie less than memories, but rules can hide in more places than one.
- `sudo nft list ruleset` — the same engine, newer syntax.
- `ss -tlnp` — who is *listening*.
- `ps aux` and `systemctl list-units --type=service` — who is *running*.
  **Port scans will not find everything on this box.** One of the intruders
  never listens on any port at all.
- `sysctl` — kernel network knobs (`net.ipv4.conf.*.rp_filter`,
  `net.ipv4.tcp_syncookies`, `...accept_redirects`). Persist settings under
  `/etc/sysctl.d/` and apply them live with `sysctl -w` or `sysctl -p`.
- `sudo ss -tlnp`, `sudo tcpdump -i any -nn` — when listening sockets aren't
  the whole story, watch what actually leaves the box.

### Hints by area

- **Firewall**: installed → enabled → default-deny incoming → allow
  established/related → allow loopback → rate-limit SSH → restrict SSH to the
  office subnet → make it survive a reboot.
- **Accounts & admin**: unauthorized users (one had no password at all), a
  service account that can log in, more than one sudo-capable user, a
  passwordless-sudo drop-in.
- **Files & keys**: a restricted file that is world-writable, a deployment
  key with loose permissions, and someone else's key in `authorized_keys`.
- **Network oddities**: a rogue listener with an obvious port, and something
  much quieter. Read every unit with `systemctl cat` — at least one is named
  to look like it belongs.

Questions? Ask in the CyberDawgs Discord.
