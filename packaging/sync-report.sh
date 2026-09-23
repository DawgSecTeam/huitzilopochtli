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

# Mirrors are written AS the user, never as root: the mirror dir is user-
# controlled, and a root cp/chown would follow a planted symlink (e.g.
# report.json -> /etc/passwd) and hand the target to that user. As the user,
# a symlink can only reach what they could already write. runuser is
# util-linux; without it, skip mirroring rather than fall back to root writes.
put_as() {  # stdin -> $2, written as user $1
    runuser -u "$1" -- sh -c 'umask 022; mkdir -p "${1%/*}" && cat > "$1"' sh "$2"
}
if ! command -v runuser >/dev/null 2>&1; then
    echo "sync-report: runuser not found; skipping report mirrors" >&2
    exit 0
fi

awk -F: '($3>=1000 && $3<60000 && $7 !~ /(nologin|false)$/) {print $1":"$6}' /etc/passwd |
while IFS=: read -r nakon_u nakon_h; do
    [ -d "$nakon_h" ] || continue
    if [ -n "$SRC" ]; then
        mirror="$nakon_h/Documents/huitzilopochtli"
        put_as "$nakon_u" "$mirror/report.html" < "$SRC" || true
        if [ -f "$SRC_JSON" ]; then
            put_as "$nakon_u" "$mirror/report.json" < "$SRC_JSON" || true
        fi
    fi
    # Legacy Desktop mirrors from pre-Documents builds: superseded by the
    # Documents copy (the shortcuts point there now). Only these two files
    # are ever removed -- the Desktop otherwise belongs to the box.
    rm -f "$nakon_h/Desktop/report.html" "$nakon_h/Desktop/report.json" 2>/dev/null || true
done

exit 0
