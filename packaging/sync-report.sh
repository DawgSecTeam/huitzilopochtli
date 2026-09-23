#!/bin/sh
# huitzilopochtli sync-report.sh -- mirrors /opt/.huitzilopochtli/report.html
# and its machine-readable companion report.json to $HOME/Documents/
# huitzilopochtli/ for every real interactive user, and removes the
# $HOME/Desktop copies earlier builds used to make.
#
# Why not the Desktop: the desktop stays at exactly the forensics answers
# file and the shortcut launchers (handbook + Scoring Report) -- the report
# icons duplicated files the shortcuts already open. Why not /opt: a browser
# installed as a strictly-confined snap (Ubuntu's default Firefox, among
# others) can only see paths under interfaces it has connected -- normally
# just `home` ($HOME), and never dot-directories inside it. Pointing a
# "Scoring Report" desktop shortcut straight at /opt/.huitzilopochtli/
# report.html opens fine as root/over SSH but shows "File not found" from
# inside such a browser, because the file is genuinely invisible to it. A
# plain folder under $HOME is the one spot that is off the Desktop yet still
# opens in the team's browser.
#
# report.json (agent/snapshot.py) is what the `huitz` CLI (agent/cli.py,
# installed as /usr/local/bin/huitz) renders from -- it searches these
# mirrors (Documents first, then the legacy Desktop copies) so score/watch/
# forensics work for any user without touching the sealed install dir.
# Mirror it alongside the HTML or the CLI falls back to stale grades.
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
[ -f "$SRC" ] || SRC=""
SRC_JSON=/opt/.huitzilopochtli/report.json

awk -F: '($3>=1000 && $3<60000 && $7 !~ /(nologin|false)$/) {print $1":"$6}' /etc/passwd |
while IFS=: read -r nakon_u nakon_h; do
    [ -d "$nakon_h" ] || continue
    if [ -n "$SRC" ]; then
        mirror="$nakon_h/Documents/huitzilopochtli"
        mkdir -p "$mirror"
        cp "$SRC" "$mirror/report.html"
        chown -R "$nakon_u":"$nakon_u" "$mirror" 2>/dev/null || true
        if [ -f "$SRC_JSON" ]; then
            cp "$SRC_JSON" "$mirror/report.json"
            chown "$nakon_u":"$nakon_u" "$mirror/report.json" 2>/dev/null || true
        fi
    fi
    # Legacy Desktop mirrors from pre-Documents builds: superseded by the
    # Documents copy (the shortcuts point there now). Only these two files
    # are ever removed -- the Desktop otherwise belongs to the box.
    rm -f "$nakon_h/Desktop/report.html" "$nakon_h/Desktop/report.json" 2>/dev/null || true
done

exit 0
