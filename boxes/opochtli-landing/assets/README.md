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
forensics` (the questions at the bottom). `huitz watch` re-grades live.

Your job: **harden this box before the next ship docks.**

> In production this port's perimeter runs on a dedicated firewall appliance
> (a pfSense box at the edge). Perimeters matter — but they do nothing for a
> box that already has an attacker living on it. This exercise is about the
> *host* firewall: netfilter, driven by raw `iptables` — the way you'll
> actually use it on a CCDC box. (This host scores raw iptables; firewall
> front-ends like ufw arrange rules differently and will not satisfy the
> audit.)

## Critical services (keep these alive)

- The **Cargo Manifest Lookup** web app must stay reachable on **port 80** —
  the dock clerks hit it all day. Whatever firewall you build has to let web
  traffic IN.
- The web app pulls manifest rows from its **MariaDB on 127.0.0.1:3306** —
  that path has to stay alive too.
- **SSH** must stay running and reachable. Your terminal IS your SSH session;
  a firewall that locks you out ends your shift. Rule zero of default-deny:
  allow your management path *before* you drop the default.

## The audit findings (what the Harbor Office is asking for)

1. Allow inbound traffic to the web app: TCP port **80** on INPUT.
2. Allow outbound traffic to MySQL: TCP port **3306** on OUTPUT.
3. Set up **default deny**: INPUT, FORWARD **and** OUTPUT policies to DROP —
   then make sure loopback, established/related, and the two services above
   still work. Over-blocking is a finding, not a fix.
4. Something answering on **port 9090** is an admin web console nobody asked
   for. Remove it — package or socket, your call — and confirm the port went
   quiet.
5. A service that **calls home** (beacon) is running on this box under a name
   that sounds almost legitimate. Find it, stop it, and disable its launcher.
6. Delete the beacon's binary from disk so it cannot be restarted by hand.
7. A **bind shell** is waiting for a connection. Kill it — and make sure it
   cannot simply come back after the next reboot.

Hints, if you want them: `ss -tlnp` shows every *listener* — but the thing in
finding 5 never listens on anything. For that one: `ps aux`,
`systemctl list-units --type=service`, and a suspicious eye on `/opt`.

## Forensics

Answer these in `huitz forensics` (they live in
`~/Desktop/Forensics-Questions.txt`):

- **Q1 (20 pts):** The beacon is phoning home. What destination **address and
  port** is it dialing?
- **Q2 (20 pts):** Same question for the bind shell: what **address and port**
  is it bound on?

## Scoring

- Graded automatically about once a minute. `huitz score` shows the current
  report; `huitz watch` follows it live.
- Checks are **weighted by difficulty** (EASY 5 / MODERATE 10 / HARD 20) —
  the report shows the point value of each finding.
- Wrong forensics answers cost nothing, so always guess.
- Do **not** delete or tamper with the scoring agent.

## Tools worth knowing

- `sudo iptables-save` and `sudo iptables -S` — read the ACTUAL ruleset.
  Policies (`-P`) are the default-deny knob; `-A` lines are the rules.
- `ss -tlnp` — who is *listening*.
- `ps aux` and `systemctl list-units --type=service` — who is *running*.
  **Port scans will not find everything on this box.** One of the intruders
  never listens on any port at all.
- `systemctl cat UNIT` — read what a service actually executes.
- `sudo tcpdump -i any -nn` — when listening sockets aren't the whole story,
  watch what actually leaves the box.

Questions? Ask in the CyberDawgs Discord.
