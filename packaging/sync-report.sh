#!/bin/sh
# huitzilopochtli sync-report.sh -- mirrors /opt/huitzilopochtli/report.html to
# $HOME/Desktop/report.html for every real interactive user.
#
# Why this exists: a browser installed as a strictly-confined snap (Ubuntu's
# default Firefox, among others) can only see paths under interfaces it has
# connected -- normally just `home` ($HOME), never /opt. Pointing a "Scoring
# Report" desktop shortcut straight at /opt/huitzilopochtli/report.html opens
# fine as root/over SSH but shows "File not found" from inside such a
# browser, because the file is genuinely invisible to it. Keeping a synced
# copy under $HOME/Desktop sidesteps that entirely.
#
# Run via huitzilopochtli-agent.service's ExecStartPost, after every agent
# run (see that unit's comments -- it also flips ProtectHome off so this can
# write into $HOME). Honor mode's periodic re-grade timer restarts that
# service every 60s, so this stays fresh automatically. Ranked mode's single
# long-running process only gets the very first snapshot synced (ExecStartPost
# fires once, at service start, not on every internal loop iteration) -- a
# known limitation, same shape as the honor/ranked asymmetry already
# documented in packaging/huitzilopochtli-agent.timer.
set -e

SRC=/opt/huitzilopochtli/report.html
[ -f "$SRC" ] || exit 0

awk -F: '($3>=1000 && $3<60000 && $7 !~ /(nologin|false)$/) {print $1":"$6}' /etc/passwd |
while IFS=: read -r nakon_u nakon_h; do
    [ -d "$nakon_h/Desktop" ] || continue
    cp "$SRC" "$nakon_h/Desktop/report.html"
    chown "$nakon_u":"$nakon_u" "$nakon_h/Desktop/report.html" 2>/dev/null || true
done

exit 0
