"""Score-board derivation — one implementation, every renderer.

The player-facing views (HTML report, `huitz` terminal UI, report.json
snapshot) all present the same derived facts: which vulnerabilities are
fixed, which penalties are active, how the forensics questions stand, and
how far along the scenario the team is. This module derives those facts
once from (ScoreBreakdown, manifest) so the renderers cannot drift — the
same reason agent/report_page.py exists for the two HTML pages.

Pure and I/O-free. Accepts both dataclass manifests and raw dicts (the
same duck typing reporter.py has always used, so engine-side callers can
pass parsed JSON). The honor board is CyberPatriot-style positive-only:
failed checks are never identified, only counted ("N issue(s) remain").
"""
from dataclasses import dataclass, field

from agent.report_page import ACCENT_RE


@dataclass
class FixedVuln:
    title: str
    points: int


@dataclass
class ActivePenalty:
    title: str
    points: int


@dataclass
class ForensicsEntry:
    id: str
    question: str
    max_points: int
    ordinal: int = 0                # answers-file ordinal (0 = unknown)
    answers_path: str = ""          # resolved by agent/__main__._prepare_forensics
    answered: bool = False          # results say this question earned its points
    points: int = 0                 # awarded on the last grade (0 when unanswered)


@dataclass
class Board:
    title: str
    organization: str | None
    accent: str | None              # validated #rrggbb, else None
    total: int
    max_possible: int
    progress_pct: int               # 0-100
    fixed: list = field(default_factory=list)       # list[FixedVuln]
    vulns_fixed: int = 0
    vulns_total: int = 0
    remaining: int = 0
    all_fixed: bool = False
    penalties: list = field(default_factory=list)   # list[ActivePenalty]
    forensics: list = field(default_factory=list)   # list[ForensicsEntry]
    forensics_earned: int = 0


def _manifest_checks(manifest) -> list:
    checks = getattr(manifest, "checks", None)
    if checks is None and isinstance(manifest, dict):
        checks = manifest.get("checks", [])
    return checks or []


def _check_field(check, name, default=None):
    if isinstance(check, dict):
        return check.get(name, default)
    return getattr(check, name, default)


def _category_str(value) -> str:
    return value.value if hasattr(value, "value") else str(value or "")


def _manifest_forensics(manifest) -> list:
    """[{id, question, max_points}] from the manifest's forensics block."""
    if manifest is None:
        return []
    forensics = getattr(manifest, "forensics", None)
    if forensics is None and isinstance(manifest, dict):
        forensics = manifest.get("forensics")
    out = []
    for fq in forensics or []:
        if isinstance(fq, dict):
            out.append({
                "id": fq.get("id"),
                "question": fq.get("question") or fq.get("id"),
                "max_points": fq.get("max_points", 0),
            })
        else:
            out.append({
                "id": getattr(fq, "id", None),
                "question": getattr(fq, "question", None) or getattr(fq, "id", None),
                "max_points": getattr(fq, "max_points", 0),
            })
    return out


def build_board(score, manifest) -> Board:
    """Derive the player-facing board from a scoring result + manifest.

    Splitting this from rendering is what lets the HTML report, the huitz
    CLI, and the report.json snapshot stay in lockstep (§13): one derivation,
    three presentations, and the unit tests pin each number once.
    """
    manifest = manifest or {}
    theme = getattr(manifest, "theme", None)
    if theme is None and isinstance(manifest, dict):
        theme = manifest.get("theme")
    theme = theme or {}

    checks = _manifest_checks(manifest)
    lookup = {
        _check_field(c, "id"): {
            "display_title": _check_field(c, "display_title") or _check_field(c, "id"),
            "display_max_points": _check_field(c, "display_max_points", 0) or 0,
            "category": _category_str(_check_field(c, "category")),
            "is_sla": bool(_check_field(c, "is_sla", False)),
            "collect_params": _check_field(c, "collect_params", {}) or {},
        }
        for c in checks
    }

    forensics_meta = _manifest_forensics(manifest)
    forensics_ids = {f["id"] for f in forensics_meta}
    results_by_id = {r.check_id: r for r in (score.results or [])}

    # --- fixed vulnerabilities + active penalties ---------------------------
    fixed = []
    penalties = []
    for r in score.results or []:
        cat = _category_str(r.category)
        title = (lookup.get(r.check_id, {}) or {}).get("display_title") or r.check_id
        if cat == "vuln":
            # Only surfaced once passed; failed vulns stay anonymous.
            if r.passed and r.awarded_points != 0 and r.check_id not in forensics_ids:
                fixed.append(FixedVuln(title=title, points=r.awarded_points))
        else:
            # penalty / prohibited: surface only when actually incurred.
            if r.awarded_points != 0:
                penalties.append(ActivePenalty(title=title, points=r.awarded_points))

    # --- progress accounting -------------------------------------------------
    # Denominators come from the manifest when available (results only ever
    # carry the checks that ran); SLA entries are engine-scored and never in
    # results, and penalty/prohibited checks add nothing to the earnable max.
    vulns_total = 0
    max_possible = 0
    for cid, info in lookup.items():
        if cid in forensics_ids or info["is_sla"]:
            continue
        if info["category"] == "vuln":
            vulns_total += 1
            max_possible += int(info["display_max_points"] or 0)
    if not lookup:
        # No manifest: fall back to what the results themselves show.
        vulns_total = sum(
            1 for r in score.results or []
            if _category_str(r.category) == "vuln" and r.check_id not in forensics_ids
        )
        max_possible = sum(max(0, r.awarded_points) for r in score.results or [])

    vulns_fixed = len(fixed)
    remaining = max(0, vulns_total - vulns_fixed)

    if max_possible <= 0:
        pct = int((vulns_fixed / vulns_total * 100) if vulns_total else 0)
    else:
        earned_positive = sum(v.points for v in fixed)
        pct = int((earned_positive / max_possible * 100) if max_possible else 0)
        if pct == 0 and vulns_total:
            pct = int((vulns_fixed / vulns_total * 100) if vulns_total else 0)
    pct = max(0, min(100, pct))

    # --- forensics ------------------------------------------------------------
    forensics = []
    for f in forensics_meta:
        r = results_by_id.get(f["id"])
        # Ordinal + answers path live on the forensics_answer CheckSpec.
        spec_info = next(
            (info for cid, info in lookup.items()
             if cid == f["id"] and info["collect_params"]),
            None,
        )
        collect_params = (spec_info or {}).get("collect_params", {})
        forensics.append(ForensicsEntry(
            id=f["id"],
            question=f["question"],
            max_points=f["max_points"],
            ordinal=collect_params.get("ordinal", 0) or 0,
            answers_path=collect_params.get("path", "") or "",
            answered=bool(r is not None and r.passed),
            points=r.awarded_points if r is not None else 0,
        ))
    forensics_earned = sum(1 for f in forensics if f.answered)

    accent = theme.get("accent")
    accent = str(accent) if accent and ACCENT_RE.match(str(accent)) else None

    return Board(
        title=theme.get("title") or getattr(score, "scenario_name", None)
        or (manifest.get("scenario_name") if isinstance(manifest, dict) else None)
        or "",
        organization=theme.get("organization"),
        accent=accent,
        total=score.total,
        max_possible=max_possible,
        progress_pct=pct,
        fixed=fixed,
        vulns_fixed=vulns_fixed,
        vulns_total=vulns_total,
        remaining=remaining,
        all_fixed=bool(vulns_total > 0 and vulns_fixed == vulns_total),
        penalties=penalties,
        forensics=forensics,
        forensics_earned=forensics_earned,
    )
