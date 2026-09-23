"""Machine-readable report snapshot (`report.json`) — the huitz CLI's source.

Every grade (honor run or ranked check-in) writes a snapshot next to the
HTML report; `packaging/sync-report.sh` mirrors both to each user's Desktop
the same way. The CLI (agent/cli.py) renders from the snapshot instead of
re-scoring, which is what lets `huitz score` / `huitz watch` / `huitz
forensics` work as ANY user on the box — including non-root desktop
accounts that cannot read the sealed install dir (§17). The snapshot is a
presentation of the ScoreBreakdown, never a scoring input (§2.1): nothing
reads it back into the evaluator.

Secrecy follows the HTML report's per-mode contract (§13):

- **honor**: CyberPatriot positive-only. Failed checks are never identified
  — no `results` list, no reasons — only the derived board (fixed titles,
  incurred penalties, forensics state, counts). Spoiler-safety survives
  `cat`, `jq`, and the Desktop copy.
- **ranked**: the rubric never touched the box, so the engine's full
  diagnostic (per-check results + SLA states) rides along, mirroring the
  ranked HTML table.

`snapshot_version` gates the format; the CLI refuses newer majors with a
clear message instead of misrendering.
"""
import json
import os
import sys

from agent import board as board_mod

SNAPSHOT_VERSION = 1
_FILENAME = "report.json"


class SnapshotError(Exception):
    """A snapshot exists but cannot be used (unreadable, corrupt, newer)."""


def snapshot_path_for(report_path: str) -> str:
    """The snapshot lives next to the HTML report (same install dir)."""
    return os.path.join(
        os.path.dirname(os.path.abspath(report_path)), _FILENAME
    )


def build_snapshot(score, manifest, *, mode: str, agent_version: str,
                   delta: int | None, computed_at: float,
                   honor_interval_s: int = 70,
                   server_time: float | None = None,
                   next_checkin_s: int | None = None,
                   awaiting_engine: bool = False) -> dict:
    """Assemble the snapshot dict. Pure; `write` serializes it.

    `mode` is "honor" | "ranked" (str, so callers need not import schema).
    Honor derives the estimated next re-grade from computed_at + the timer
    cadence; ranked anchors to the engine's server_time + next_checkin_s.
    Both are display estimates for a countdown, never scoring inputs (§13).
    The honor default is 70s, not the timer's OnUnitActiveSec=60: the unit
    re-fires 60s after the previous ACTIVATION, and a grade takes ~2s plus
    dispatch, so observed fires land ~70s apart — a 60s estimate spends the
    last stretch of every cycle pinned at "00:00 — checking…".
    """
    b = board_mod.build_board(score, manifest)
    theme = getattr(manifest, "theme", None)
    if theme is None and isinstance(manifest, dict):
        theme = manifest.get("theme")
    theme = theme or {}
    snap = {
        "snapshot_version": SNAPSHOT_VERSION,
        "agent_version": agent_version,
        "mode": mode,
        "scenario_name": score.scenario_name,
        "scenario_version": score.scenario_version,
        "title": b.title,
        "organization": b.organization,
        "accent": b.accent,
        # Handbook text embedded by the compiler (theme.readme); None when
        # the scenario ships none. `huitz readme` renders it in the terminal.
        "readme": theme.get("readme_text"),
        "awaiting_engine": awaiting_engine,
        # null (not 0) while awaiting the engine: no score exists yet.
        "total": None if awaiting_engine else b.total,
        "max_possible": b.max_possible,
        "progress_pct": b.progress_pct,
        "fixed": [{"title": v.title, "points": v.points} for v in b.fixed],
        "vulns_fixed": b.vulns_fixed,
        "vulns_total": b.vulns_total,
        "remaining": b.remaining,
        "all_fixed": b.all_fixed,
        "penalties": [{"title": p.title, "points": p.points} for p in b.penalties],
        "forensics": [
            {
                "id": f.id,
                "ordinal": f.ordinal,
                "question": f.question,
                "max_points": f.max_points,
                "answered": f.answered,
                "points": f.points,
                "answers_path": f.answers_path,
            }
            for f in b.forensics
        ],
        "forensics_earned": b.forensics_earned,
        "delta": delta,
        "computed_at": computed_at,
        "next_event_at": None,
        "last_confirmed_at": None,
        "next_checkin_s": None,
        "sla_status": [],
    }

    if mode == "ranked":
        # Diagnostic detail is safe here and only here: the rubric never
        # shipped to this box (§2.4), so results leak no answer key.
        snap["results"] = [
            {
                "check_id": r.check_id,
                "category": getattr(getattr(r, "category", None), "value",
                                    str(getattr(r, "category", ""))),
                "awarded_points": r.awarded_points,
                "passed": bool(r.passed),
                "reason": r.reason,
            }
            for r in (score.results or [])
        ]
        snap["sla_status"] = [
            {
                "check_id": s.check_id,
                "state": s.state,
                "accrued_points": s.accrued_points,
            }
            for s in (score.sla_status or [])
        ]
        snap["last_confirmed_at"] = server_time
        snap["next_checkin_s"] = next_checkin_s
        if server_time is not None and isinstance(next_checkin_s, (int, float)) \
                and not isinstance(next_checkin_s, bool) and next_checkin_s > 0:
            snap["next_event_at"] = float(server_time) + float(next_checkin_s)
    else:
        snap["next_event_at"] = float(computed_at) + float(honor_interval_s)

    return snap


def write(report_path: str, snapshot: dict) -> bool:
    """Write the snapshot next to the HTML report (atomic, world-readable).

    0644 on purpose: the file is mirrored into every user's Documents/
    huitzilopochtli dir (packaging/sync-report.sh) and, in either mode,
    carries nothing the synced HTML wouldn't. Returns False
    (after a WARNING) instead of raising — cosmetics must never stall a
    grade (§9.1).
    """
    path = snapshot_path_for(report_path)
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=1)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
        return True
    except OSError as e:
        print(f"WARNING: could not write snapshot {path!r}: {e}", file=sys.stderr)
        try:
            os.remove(tmp)
        except OSError:
            pass
        return False


def read(path: str) -> dict:
    """Load + sanity-check a snapshot. Raises SnapshotError with a message
    meant for the terminal (the CLI surfaces it verbatim)."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except OSError as e:
        raise SnapshotError(f"cannot read {path}: {e}") from e
    except ValueError as e:
        raise SnapshotError(f"{path} is not valid JSON ({e})") from e

    if not isinstance(data, dict):
        raise SnapshotError(f"{path} is not a snapshot file")
    version = data.get("snapshot_version")
    if not isinstance(version, int) or isinstance(version, bool):
        raise SnapshotError(f"{path} has no snapshot_version — not a huitz snapshot")
    if version > SNAPSHOT_VERSION:
        raise SnapshotError(
            f"{path} is snapshot v{version}, but this huitz understands up to "
            f"v{SNAPSHOT_VERSION}; update the agent on this box"
        )
    return data
