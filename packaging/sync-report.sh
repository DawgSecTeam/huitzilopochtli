#!/bin/sh
# huitzilopochtli sync-report.sh -- mirrors /opt/.huitzilopochtli/report.html
# + report.json to $HOME/Documents/huitzilopochtli/ for every real
# interactive user, and removes the legacy $HOME/Desktop copies.
# Why not the Desktop: it stays exactly the forensics answers file + the
# shortcut launchers; report icons duplicated files the shortcuts open.
# Why not /opt: strictly snap-confined browsers (Ubuntu's default Firefox)
# see only plain `home` paths (never dot-directories) — a shortcut pointed
# at /opt opens "File not found" inside them.
# report.json is what the `huitz` CLI renders from (it searches these
# mirrors), so skipping it shows players stale grades.
# Run by the agent at the end of every honor grade
# (agent/__main__.py::_sync_desktop_copies) and, as first-snapshot/
# fallback, by huitzilopochtli-agent.service's ExecStartPost (which is why
# that unit flips ProtectHome off).
set -e

SRC=/opt/.huitzilopochtli/report.html
[ -f "$SRC" ] || SRC=""
SRC_JSON=/opt/.huitzilopochtli/report.json

# Mirrors are written AS the user, never as root: a root cp into this
# user-controlled dir would follow a planted symlink (report.json ->
# /etc/passwd). Without runuser, skip mirroring rather than write as root.
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
    # Legacy pre-Documents copies (shortcuts point at Documents now). Only
    # these two files are ever removed -- the Desktop belongs to the box.
    rm -f "$nakon_h/Desktop/report.html" "$nakon_h/Desktop/report.json" 2>/dev/null || true
done

exit 0
