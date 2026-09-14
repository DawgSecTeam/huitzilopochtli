#!/bin/sh
# huitzilopochtli sync-report.sh -- mirrors /opt/.huitzilopochtli/report.html
# and its machine-readable companion report.json to $HOME/Desktop for every
# real interactive user.
#
# Why this exists: a browser installed as a strictly-confined snap (Ubuntu's
# default Firefox, among others) can only see paths under interfaces it has
# connected -- normally just `home` ($HOME), never /opt. Pointing a "Scoring
# Report" desktop shortcut straight at /opt/.huitzilopochtli/report.html opens
# fine as root/over SSH but shows "File not found" from inside such a
# browser, because the file is genuinely invisible to it. Keeping a synced
# copy under $HOME/Desktop sidesteps that entirely.
#
# report.json (agent/snapshot.py) is what the `huitz` CLI (agent/cli.py,
# installed as /usr/local/bin/huitz) renders from -- it reads the Desktop
# copy so score/watch/forensics work for any user without touching the
# sealed install dir. Mirror it alongside the HTML or the CLI falls back to
# stale grades.
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

SRC=/opt/.huitzilopochtli/report.html
[ -f "$SRC" ] || exit 0
SRC_JSON=/opt/.huitzilopochtli/report.json

awk -F: '($3>=1000 && $3<60000 && $7 !~ /(nologin|false)$/) {print $1":"$6}' /etc/passwd |
while IFS=: read -r nakon_u nakon_h; do
    [ -d "$nakon_h/Desktop" ] || continue
    cp "$SRC" "$nakon_h/Desktop/report.html"
    chown "$nakon_u":"$nakon_u" "$nakon_h/Desktop/report.html" 2>/dev/null || true
    if [ -f "$SRC_JSON" ]; then
        cp "$SRC_JSON" "$nakon_h/Desktop/report.json"
        chown "$nakon_u":"$nakon_u" "$nakon_h/Desktop/report.json" 2>/dev/null || true
    fi
done

exit 0
