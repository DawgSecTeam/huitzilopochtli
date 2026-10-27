#!/bin/sh
# Fix the "black VNC screen / invisible desktop" failure mode on a headless
# XFCE image served over x11vnc: the X session is up, but nothing renders.
#
# SYMPTOM: VNC shows a solid black screen while the cursor still moves --
# x11vnc tracks/draws the pointer separately from the framebuffer capture, so
# a live cursor is NOT proof the session is rendering. Direct `xwd` capture of
# the X display (bypassing VNC entirely) shows the same thing, so this is the
# X session, not a VNC-layer artifact. If you verify by hand, convert the XWD
# with netpbm, not ImageMagick -- `convert`/`import` mis-decode this xwd's
# colour format and produce a false all-black image:
#   apt-get install -y netpbm && xwdtopnm shot.xwd | pnmtopng > shot.png
#
# CAUSE: up to three independent, compounding blanking failures --
#   1. no lightdm autologin: whoever built the image logged into the greeter
#      once and never rebooted, so any reboot (or `systemctl restart lightdm`)
#      drops back to a real login prompt nobody can answer -- a dark screen
#      with a live cursor, which is what most black-screen reports really are;
#   2. DPMS screen blanking (`xset q` reports "Monitor is Off") after ~20 min
#      idle, with xfce4-power-manager independently re-asserting its own
#      DPMS/blank timers regardless of raw `xset` settings;
#   3. xfce4-screensaver's own idle activation (a separate subsystem from
#      DPMS) painting a fullscreen black lock/blank window.
# Any one of them alone reproduces "solid black, cursor moves".
#
# WHAT IT DOES: truncates /etc/machine-id so every future clone generates its
# own id at first boot, writes a lightdm autologin drop-in, makes x11vnc and
# xfce4-power-manager never DPMS-blank, and disables xfce4-screensaver idle
# activation (deactivating an already-painted instance too).
#
# Run once as root on a booted clone before sealing it. Idempotent -- safe to
# re-run. Usage:
#   ssh <user>@<clone-ip> 'sudo sh -s' < fix-xubuntu-vnc-display.sh -- <login_user>
# <login_user> is the account whose desktop is actually shown over VNC (the
# one lightdm should autologin) -- not necessarily the account the tooling
# provisions over SSH. Confirm with `who`/`loginctl list-sessions` on a
# currently-running clone before assuming the name.

set -e

LOGIN_USER="${1:?usage: $0 <login-user-to-autologin>}"

# xfconf-query needs a D-Bus session bus. `dbus-launch --exit-with-session`
# spins up a throwaway one -- correct if nobody is logged in yet, but WRONG
# if lightdm autologin has already started a real session for $u by the time
# this script runs (true whenever this runs post-boot against an
# already-autologinned clone, which is the normal case here): the write goes
# to a disposable xfconfd instance the real, already-running session never
# sees, and silently vanishes -- it can report "disabled" while the property
# never existed on the live session's bus, and the screensaver's fullscreen
# window keeps painting solid black over the whole desktop. Prefer the REAL
# per-user bus at /run/user/<uid>/bus (created by an actual login) when it's
# there; only fall back to a throwaway dbus-launch bus if no session has
# started yet.
run_as_user_dbus() {
  _u="$1"; shift
  _uid=$(id -u "$_u")
  if [ -S "/run/user/$_uid/bus" ]; then
    sudo -u "$_u" env "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$_uid/bus" "$@"
  else
    sudo -u "$_u" dbus-launch --exit-with-session "$@"
  fi
}

echo "== 0. machine-id (DHCP-collision hygiene) =="
# A template built from another template inherits the source's /etc/machine-id
# verbatim unless it's explicitly re-wiped after the clone: two live clones
# then share one DHCP client id and grab the SAME IP.
#
# IMPORTANT: leave the file EMPTY here -- do NOT run
# systemd-machine-id-setup (which writes a value immediately, derived from
# THIS VM's current SMBIOS UUID). A value written now is exactly as wrong
# as the bug this fixes: it becomes the ONE machine-id every future clone
# of the resulting template inherits, reproducing the same collision the
# next time two of those clones are live at once. Left empty, systemd
# generates a fresh id itself, very early at boot (before networking), from
# each clone's OWN vm UUID -- which is what actually needs to be unique per
# clone, not per template.
rm -f /etc/machine-id
touch /etc/machine-id
echo "   /etc/machine-id truncated to empty -- each future clone of the"
echo "   resulting template will generate its own fresh id at first boot."
echo "   (If you're applying this fix live, on a VM that must ALSO stay"
echo "   usable right now rather than be re-sealed immediately, run"
echo "   'systemd-machine-id-setup' yourself afterward to populate it for"
echo "   this boot -- just don't do that on the copy you're about to"
echo "   re-seal as a template.)"

echo "== 1. lightdm autologin for '$LOGIN_USER' =="
mkdir -p /etc/lightdm/lightdm.conf.d
# Session id is the .desktop file's basename WITHOUT the .desktop suffix
# (see /usr/share/xsessions/*.desktop) -- using the full filename here is
# a silent no-op ("Failed to find session configuration", falls back to
# the greeter).
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
  run_as_user_dbus "$u" xfconf-query \
    -c xfce4-power-manager -p /xfce4-power-manager/dpms-enabled \
    -n -t bool -s false 2>/dev/null || true
  for prop in blank-on-ac blank-on-battery dpms-on-ac-off \
              dpms-on-ac-sleep dpms-on-battery-off dpms-on-battery-sleep; do
    run_as_user_dbus "$u" xfconf-query \
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
  run_as_user_dbus "$u" xfconf-query \
    -c xfce4-screensaver -p /saver/idle-activation/enabled \
    -n -t bool -s false 2>/dev/null || true
  # Disabling idle-activation only stops FUTURE triggers -- if the
  # screensaver already painted its fullscreen window before this script
  # ran (observed happening immediately after lightdm autologin, well
  # before boxbuilder/this fix gets a chance to run), that window stays up
  # until explicitly told to go away.
  run_as_user_dbus "$u" xfce4-screensaver-command --deactivate 2>/dev/null || true
  echo "   disabled xfce4-screensaver idle-activation (and deactivated any"
  echo "   already-active instance) for $u"
done

echo "== done =="
echo "Reboot (or restart lightdm) and confirm via 'xset q' (DPMS disabled,"
echo "Monitor stays On) and 'loginctl list-sessions' (a real desktop"
echo "session for $LOGIN_USER on seat0, not just a stuck greeter) before"
echo "re-sealing this VM as a template."
