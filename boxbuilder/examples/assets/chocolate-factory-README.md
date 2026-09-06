# Cocoa Falls Chocolate Works — hardening tour

Welcome to the factory systems tour. The box is a normal Ubuntu/Xubuntu XFCE
workstation with a fictional chocolate-factory wrapper. You do **not** need to
know any story or brand to solve it: use standard Linux administration and
incident-response habits.

## Tour brief

You are the incoming systems custodian. Restore a safe baseline before the next
production shift. The scoring report rewards the secure end state, not a
particular command or tool.

Start with the ordinary checks:

- Review `/etc/passwd`, `/etc/shadow`, and the `sudo` group.
- Check SSH settings, sudoers drop-ins, and the admin's `authorized_keys`.
- Inspect permissions on recipe, scheduled-job, key, and Desktop files.
- Review `/etc/cron.d`, user crontabs, and enabled services.
- Treat a file's extension as untrusted; inspect the shared media shelf.

New to this? A few findings don't need a terminal at all: unexpected
accounts show up as extra tiles on the login screen before you even reach
a desktop, and a stray autostart entry is a checkbox in Settings > Session
and Startup > Application Autostart. Start there, then work into the ones
that need a terminal.

## A fair way to work

1. Record what you find before changing it.
2. Prefer the least disruptive fix that restores the expected baseline.
3. Validate syntax before restarting a service or changing an access-control file.
4. Re-check both the direct artifact and the mechanism that launches it.
5. Do not delete the scoring agent or its installation directory.

The difficult findings are meant to reward careful enumeration: look for hidden
paths, startup hooks, and services that do not belong on a workstation. A clean
service state is not enough if its unit file or launcher remains behind.

## Useful, non-prescriptive commands

```text
id; getent passwd; getent group sudo
sudo -l
sshd -T 2>/dev/null | grep -i permitrootlogin
find /etc/cron.d /var/spool/cron -maxdepth 3 -type f -ls 2>/dev/null
systemctl list-unit-files --state=enabled
file /var/media/* 2>/dev/null
```

When finished, open **Scoring Report** on the desktop. The report explains which
checks passed and gives the evidence collected by the agent.

This is an authorized training image. The payloads planted for the exercise are
harmless, but they model patterns that should be investigated on real systems.
