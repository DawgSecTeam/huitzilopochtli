#!/bin/sh
# Fix for the "black VNC screen / invisible desktop (incl. scoreboard
# shortcuts)" failure mode on xubuntu-vnc-derived templates (xubuntu-vnc
# vmid 119, chocolate-factory-template vmid 129 and its descendants).
#
# Run this ONCE, as root, on a booted clone of the template before
# re-sealing it (`qm template`). It is idempotent -- safe to re-run.
#
# BACKGROUND (2026-09-05 incident, see boxbuilder/README.md's "VNC desktop
# caveats" section and boxbuilder/examples/chocolate-factory.box.yaml):
#
# A live student box showed a solid-black VNC screen (cursor still moved --
# x11vnc tracks/draws the pointer separately from the framebuffer capture,
# so a live cursor is NOT proof the session is actually rendering) and no
# visible desktop icons, including the huitzilopochtli "Scoring Report"
# shortcut. Direct `xwd`-based capture of the real X display (bypassing
# VNC/Guacamole entirely) proved this was genuine -- the X session itself
# had nothing rendered, not a VNC-layer artifact. NOTE: if you try this
# yourself to double check, don't reach for ImageMagick's `convert`/
# `import` for the XWD -> PNG conversion -- it mis-decodes this xwd's
# color format and renders a false all-black image. Use netpbm instead:
#   apt-get install -y netpbm && xwdtopnm shot.xwd | pnmtopng > shot.png
#
# Root cause, found by process of elimination against a live clone:
#
#   1. THE BIG ONE: xubuntu-vnc was never actually configured for lightdm
#      autologin. Whoever built the template originally just typed the
#      account's password into the greeter once, and it stuck because the
#      VM was never rebooted again. Any reboot (or `systemctl restart
#      lightdm`) drops back to a real login greeter that nobody -- not the
#      student, not the automation -- has credentials to answer, which
#      sits there indefinitely with a dark/blank background and a live
#      cursor. This is very likely what the *original* black-screen
#      reports actually were. Fixed by section 1 below.
#   2. DPMS screen blanking (`xset q` reporting "Monitor is Off") after
#      ~20 min idle, compounded by xfce4-power-manager independently
#      re-asserting its own DPMS/blank timers regardless of raw `xset`
#      settings. Fixed by section 2 below.
#   3. xfce4-screensaver's own idle-activation (a separate subsystem from
#      DPMS) painting a fullscreen black lock/blank window. Fixed by
#      section 3 below.
#
# All three are independent and compounding -- fix all three, since any
# one of them alone reproduces "solid black, cursor moves".
#
# Usage: scp this script to the booted clone and run as root, e.g.:
#   ssh <user>@<clone-ip> 'sudo sh -s' < fix-xubuntu-vnc-display.sh -- <login_user>
# where <login_user> is the account whose desktop is actually shown over
# VNC (the account lightdm should autologin -- for chocolate-factory this
# is "sysadmin", NOT the "ubuntu" account boxbuilder provisions over SSH;
# confirm with `who`/`loginctl list-sessions` on a currently-running clone
# before assuming the name).

set -e

LOGIN_USER="${1:?usage: $0 <login-user-to-autologin>}"

echo "== 0. machine-id (DHCP-collision hygiene) =="
# A template built from another template (e.g. chocolate-factory-template
# from xubuntu-vnc) inherits the source's /etc/machine-id verbatim unless
# it's explicitly re-wiped after the clone -- confirmed the hard way
# (2026-09-05): a fresh clone of chocolate-factory-template (vmid 129)
# grabbed the SAME DHCP IP as an already-running sibling clone because both
# shared one machine-id. This is the same class of bug already documented
# in tests/README.md for the plain xubuntu template -- it just hadn't been
# re-applied after xubuntu-vnc was customized into chocolate-factory-template.
#
# IMPORTANT: leave the file EMPTY here -- do NOT run
# systemd-machine-id-setup (which writes a value immediately, derived from
# THIS VM's current SMBIOS UUID). A value written now is exactly as wrong
# as the bug this fixes: it becomes the ONE machine-id every future clone
# of the resulting template inherits, reproducing the same collision the
# next time two of those clones are live at once (confirmed by making this
# exact mistake once already: see the first attempt at this fix in git
# history). Left empty, systemd generates a fresh id itself, very early at
# boot (before networking), from each clone's OWN vm UUID -- which is what
# actually needs to be unique per clone, not per template.
rm -f /etc/machine-id
touch /etc/machine-id
echo "   /etc/machine-id truncated to empty -- each future clone of the"
echo "   resulting template will generate its own fresh id at first boot."
echo "   (If you're applying this fix live, on a VM that must ALSO stay"
echo "   usable right now rather than be re-sealed immediately, run"
echo "   'systemd-machine-id-setup' yourself afterward to populate it for"
echo "   this boot -- just don't do that on the copy you're about to"
echo "   re-seal with 'qm template'.)"

echo "== 1. lightdm autologin for '$LOGIN_USER' =="
mkdir -p /etc/lightdm/lightdm.conf.d
# Session id is the .desktop file's basename WITHOUT the .desktop suffix
# (see /usr/share/xsessions/*.desktop) -- using the full filename here is
# a silent no-op ("Failed to find session configuration", falls back to
# the greeter) and is the mistake that cost the most time to catch during
# the incident above.
SESSION_ID=$(basename "$(ls /usr/share/xsessions/*.desktop 2>/dev/null | grep -i xubuntu | head -1)" .desktop)
SESSION_ID="${SESSION_ID:-xubuntu}"
cat > /etc/lightdm/lightdm.conf.d/50-autologin.conf <<EOF
[Seat:*]
autologin-user=$LOGIN_USER
autologin-user-timeout=0
autologin-session=$SESSION_ID
EOF
echo "   wrote /etc/lightdm/lightdm.conf.d/50-autologin.conf (session=$SESSION_ID)"

echo "== 2. x11vnc + xfce4-power-manager: never DPMS-blank =="
# Belt 1: x11vnc's own "-nodpms" flag (counterintuitive name -- per
# `man x11vnc`, default is actually "-dpms", i.e. do nothing; "-nodpms"
# is the one that ACTS, running the equivalent of `xset dpms force on`
# periodically while a viewer is connected). This does NOT change what
# `xset q` reports (DPMS stays "Enabled" -- that's expected, not a sign
# the flag didn't take) -- it just keeps force-waking the monitor so nothing
# else's blanking (a screensaver, some other idle timer) can make it stick.
X11VNC_UNIT=/etc/systemd/system/x11vnc.service
if [ -f "$X11VNC_UNIT" ] && ! grep -q -- '-nodpms' "$X11VNC_UNIT"; then
  sed -i 's/^ExecStart=\(.*\)$/ExecStart=\1 -nodpms/' "$X11VNC_UNIT"
  systemctl daemon-reload
  echo "   added -nodpms to $X11VNC_UNIT"
else
  echo "   $X11VNC_UNIT already has -nodpms (or doesn't exist -- check manually)"
fi

# Belt 2: xfce4-power-manager independently re-engages its own DPMS/blank
# timers regardless of raw `xset` settings, so it must be told directly,
# not just the X server. Run this against every real login candidate's
# xfconf, not just $LOGIN_USER, since a future scenario author may pick a
# different account.
for home in /home/*; do
  u=$(basename "$home")
  uid=$(id -u "$u" 2>/dev/null) || continue
  [ "$uid" -ge 1000 ] 2>/dev/null || continue
  [ "$uid" -lt 60000 ] 2>/dev/null || continue
  RUNTIME_DIR="/run/user/$uid"
  mkdir -p "$RUNTIME_DIR"
  chown "$u:$u" "$RUNTIME_DIR"
  # xfconf needs a DBus session bus; dbus-launch spins up a throwaway one
  # since nobody is logged in when this runs (root, over SSH/serial).
  sudo -u "$u" dbus-launch --exit-with-session xfconf-query \
    -c xfce4-power-manager -p /xfce4-power-manager/dpms-enabled \
    -n -t bool -s false 2>/dev/null || true
  for prop in blank-on-ac blank-on-battery dpms-on-ac-off \
              dpms-on-ac-sleep dpms-on-battery-off dpms-on-battery-sleep; do
    sudo -u "$u" dbus-launch --exit-with-session xfconf-query \
      -c xfce4-power-manager -p "/xfce4-power-manager/$prop" \
      -n -t int -s 0 2>/dev/null || true
  done
  echo "   neutralized xfce4-power-manager DPMS/blank timers for $u"
done

echo "== 3. xfce4-screensaver: disable idle-activation (separate from DPMS) =="
for home in /home/*; do
  u=$(basename "$home")
  uid=$(id -u "$u" 2>/dev/null) || continue
  [ "$uid" -ge 1000 ] 2>/dev/null || continue
  [ "$uid" -lt 60000 ] 2>/dev/null || continue
  sudo -u "$u" dbus-launch --exit-with-session xfconf-query \
    -c xfce4-screensaver -p /saver/idle-activation/enabled \
    -n -t bool -s false 2>/dev/null || true
  echo "   disabled xfce4-screensaver idle-activation for $u"
done

echo "== done =="
echo "Reboot (or restart lightdm) and confirm via 'xset q' (DPMS disabled,"
echo "Monitor stays On) and 'loginctl list-sessions' (a real desktop"
echo "session for $LOGIN_USER on seat0, not just a stuck greeter) before"
echo "re-sealing this VM with 'qm template'."
