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
import math
import os
import sys
import time

from agent import board as board_mod
from agent import term as term_mod

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
            # Countdown must be anchored to the box receipt time, not the
            # engine clock: the browser/CLI compares it with Date.now()/
            # time.time() (box clock). Using server_time made a skewed box
            # clock show 00:00 (or 11:00) for the whole interval.
            snap["next_event_at"] = time.time() + float(next_checkin_s)
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


def _is_number(value) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(value)
    )


def _validate_snapshot(data: dict, path: str) -> None:
    """Validate the fields the CLI dereferences, so a corrupt/forged snapshot
    produces a clean SnapshotError instead of a ValueError/TypeError trace."""
    errors = []

    def bad(msg):
        errors.append(msg)

    mode = data.get("mode")
    if mode not in ("honor", "ranked"):
        bad("mode must be 'honor' or 'ranked'")
    if data.get("total") is not None and (
        isinstance(data.get("total"), bool) or not isinstance(data.get("total"), int)
    ):
        bad("total must be an integer or null")
    pct = data.get("progress_pct")
    if pct is not None and (
        isinstance(pct, bool) or not isinstance(pct, int) or not 0 <= pct <= 100
    ):
        bad("progress_pct must be an integer in 0..100")
    for key in ("computed_at", "next_event_at", "last_confirmed_at"):
        if data.get(key) is not None and not _is_number(data.get(key)):
            bad(f"{key} must be a finite number or null")
    if data.get("next_checkin_s") is not None and (
        isinstance(data.get("next_checkin_s"), bool)
        or not isinstance(data.get("next_checkin_s"), int)
    ):
        bad("next_checkin_s must be an integer or null")
    if data.get("delta") is not None and (
        isinstance(data.get("delta"), bool) or not isinstance(data.get("delta"), int)
    ):
        bad("delta must be an integer or null")
    if data.get("awaiting_engine") is not None and not isinstance(
            data.get("awaiting_engine"), bool):
        bad("awaiting_engine must be a boolean")

    def check_list(key, fields):
        rows = data.get(key)
        if rows is None:
            return
        if not isinstance(rows, list):
            bad(f"{key} must be a list")
            return
        for i, row in enumerate(rows):
            if not isinstance(row, dict):
                bad(f"{key}[{i}] must be an object")
                continue
            for field, kind in fields:
                value = row.get(field)
                if kind == "str" and not isinstance(value, str):
                    bad(f"{key}[{i}].{field} must be a string")
                elif kind == "int" and (
                        isinstance(value, bool) or not isinstance(value, int)):
                    bad(f"{key}[{i}].{field} must be an integer")
                elif kind == "bool" and not isinstance(value, bool):
                    bad(f"{key}[{i}].{field} must be a boolean")

    check_list("fixed", [("title", "str"), ("points", "int")])
    check_list("penalties", [("title", "str"), ("points", "int")])
    check_list("forensics", [
        ("id", "str"), ("ordinal", "int"), ("question", "str"),
        ("max_points", "int"), ("answered", "bool"), ("points", "int"),
        ("answers_path", "str"),
    ])
    check_list("results", [
        ("check_id", "str"), ("category", "str"), ("awarded_points", "int"),
        ("passed", "bool"), ("reason", "str"),
    ])
    check_list("sla_status", [
        ("check_id", "str"), ("state", "str"), ("accrued_points", "int"),
    ])
    for key in ("snapshot_version", "scenario_version", "vulns_fixed",
                "vulns_total", "remaining", "max_possible", "forensics_earned"):
        value = data.get(key)
        if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
            bad(f"{key} must be an integer")
    for key in ("scenario_name", "title", "organization", "readme",
                "agent_version", "accent"):
        value = data.get(key)
        if value is not None and not isinstance(value, str):
            bad(f"{key} must be a string or null")
    if data.get("accent") is not None and not board_mod.ACCENT_RE.match(data["accent"]):
        # Drop an invalid accent rather than abort the whole report; it is
        # cosmetic, and the renderer already guards.
        data["accent"] = None

    if errors:
        raise SnapshotError(
            f"{path} is not a usable huitz snapshot: " + "; ".join(errors[:6]))


def _sanitize_strings(value):
    if isinstance(value, str):
        return term_mod.sanitize_text(value)
    if isinstance(value, dict):
        return {k: _sanitize_strings(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_strings(v) for v in value]
    return value


def read(path: str) -> dict:
    """Load + validate a snapshot. Raises SnapshotError with a message meant
    for the terminal (the CLI surfaces it verbatim)."""
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
    _validate_snapshot(data, path)
    return _sanitize_strings(data)
