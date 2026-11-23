# Opochtli Landing Port Authority — IT Department Debrief

Welcome aboard. You are the new IT hire at the **Opochtli Landing Port
Authority**, the harbor gateway where the region's cargo comes and goes —
including the chocolate concentrate for Cocoa Falls Chocolate Works and the
telescope optics bound for Coyolxauhqui Ridge Solar Observatory. Both of those
organizations made the news recently for the *wrong* reasons, and both of them
ship through your docks.

An audit just found that this gateway host was already broken into. Your
predecessor left in a hurry. Everything the attackers touched is still here.

This box has no desktop — you work from the terminal. Start with `huitz score`
(your current standing), `huitz readme` (this handbook again), and `huitz
forensics` (the question file). `huitz watch` re-grades live.

Your job: **harden this box before the next ship docks.**

> In production this port's perimeter runs on a dedicated firewall appliance
> (a pfSense box at the edge). Perimeters matter — but they do nothing for a
> box that already has an attacker living on it. This exercise is about the
> *host* firewall: netfilter, driven by raw `iptables` — the way you'll
> actually use it on a CCDC box. (This host scores raw iptables; firewall
> front-ends like ufw arrange rules differently and will not satisfy the
> audit.)

## Critical services (keep these alive)

- The **Cargo Manifest Lookup** web app must stay reachable — the dock
  clerks hit it all day. Whatever firewall you build has to let its traffic
  IN.
- The web app pulls manifest rows from the harbor's shared **MariaDB** (it
  is not on this box) — that outbound path has to stay alive too.
- **SSH** must stay running and reachable. Your terminal IS your SSH session;
  a firewall that locks you out ends your shift. Rule zero of default-deny:
  allow your management path *before* you drop the default.

## Where to look

The audit says the box is compromised. Rather than a checklist, these are
the places an intruder leaves traces — work through them and let the
evidence tell you what actually happened:

- **The firewall.** Set up a **default deny** policy — and make sure the
  critical services above still work through it. Discover what each service
  actually needs *before* you drop the default; over-blocking is a finding,
  not a fix.
- **Listeners.** Something may be answering on a port nobody asked for.
  Find anything that should not be there and make sure it stays gone.
- **Running software.** Something may be running that calls home, under a
  name that sounds almost legitimate. Find it — and find everything that
  would restart it, because stopping one process is not enough if a service,
  a timer, or a startup hook launches it again.
- **Persistence.** Check the places software hides so it survives a reboot
  and manual restarts alike.

## Forensics

Scored questions live in `~/Desktop/Forensics-Questions.txt` — answer them
in `huitz forensics`. Each wants one short, specific answer.

## Scoring

- Graded automatically about once a minute. `huitz score` shows the current
  report; `huitz watch` follows it live.
- Checks are **weighted by difficulty** (EASY 5 / MODERATE 10 / HARD 20).
- Wrong forensics answers cost nothing, so always guess.
- Do **not** delete or tamper with the scoring agent.

## Tools worth knowing

- `sudo iptables-save` and `sudo iptables -S` — read the ACTUAL ruleset.
  Policies (`-P`) are the default-deny knob; `-A` lines are the rules.
- `ss -tlnp` — who is *listening*.
- `ps aux` and `systemctl list-units --type=service` — who is *running*.
  **Port scans will not find everything on this box.**
- `systemctl cat UNIT` — read what a service actually executes.
- `sudo tcpdump -i any -nn` — when listening sockets aren't the whole story,
  watch what actually leaves the box.

Questions? Ask in the CyberDawgs Discord.
