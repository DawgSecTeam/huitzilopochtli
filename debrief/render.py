"""PDF rendering for the debrief tool.

fpdf2, no engine imports: a debrief PDF is a plain document generated from
the digest + narrative dicts. Layout decisions (what gets a table, what gets
a bullet, what gets a page break) live here and nowhere else.
"""

from __future__ import annotations

import unicodedata
from pathlib import Path
from typing import Optional

from fpdf import FPDF
from fpdf.enums import XPos, YPos

ACCENT = (31, 78, 121)      # composed, non-alarming blue
MUTED = (110, 118, 130)
GOOD = (46, 125, 50)
WARN = (176, 28, 46)

PAGE_W = 210.0
PAGE_H = 297.0
MARGIN = 16.0
CONTENT_W = PAGE_W - 2 * MARGIN

# The core fonts are latin-1 (cp1252)-only; every string that reaches a
# cell goes through _ascii so a stray em-dash or a non-latin team name
# degrades to a lookalike instead of killing the render.
_TRANSLATE = {
    "\u2014": "-", "\u2013": "-", "\u2018": "'", "\u2019": "'",
    "\u201c": '"', "\u201d": '"', "\u2022": "-", "\u00a0": " ",
    "\u2026": "...",
}


def _ascii(text: object) -> str:
    if text is None:
        return ""
    text = str(text)
    for src, dst in _TRANSLATE.items():
        text = text.replace(src, dst)
    return unicodedata.normalize("NFKD", text).encode(
        "latin-1", "replace").decode("latin-1")


def render_pdf(digest: dict, out_path: Path) -> Path:
    """Render one team's debrief into out_path. Returns the path written."""
    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    _header(pdf, digest)
    _score_section(pdf, digest)
    _detail_section(pdf, digest)
    _narrative_section(pdf, digest)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(out_path))
    return out_path


# --- sections ---------------------------------------------------------------


def _header(pdf: FPDF, digest: dict) -> None:
    pdf.set_font("Helvetica", "B", 17)
    pdf.set_text_color(20, 20, 20)
    pdf.cell(0, 10, text=_ascii("Team debrief"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(90, 90, 90)
    comp = digest.get("competition", {})
    digest_str = _fmt_date(comp.get("started_at"))
    pdf.cell(0, 7, text=_ascii(f"run over {comp.get('name', '?')}, {digest_str}"),
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    team_name = (digest.get("team") or {}).get("display_name")
    if team_name:
        pdf.cell(0, 7, text=_ascii(f"Prepared for team: {team_name}"),
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)


def _score_section(pdf: FPDF, digest: dict) -> None:
    team = digest["team"]

    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(20, 20, 20)
    pdf.cell(0, 8, text=_ascii("How this run went"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1)

    total = team.get("score", {}).get("total", 0)
    hardening = team.get("score", {}).get("hardening_points")
    service = team.get("score", {}).get("service_points")
    max_total = team.get("score", {}).get("max_total")
    rank = team.get("rank")
    rank_total = team.get("rank_total")

    rows = [("Final score", _fmt_num(total))]
    if hardening is not None:
        rows.append(("Check points", _fmt_num(hardening)))
    if service is not None:
        rows.append(("Service uptime points", _fmt_num(service)))
    if max_total:
        rows.append(("Best possible on this scenario", _fmt_num(max_total)))
    if rank is not None and rank_total is not None:
        rows.append(("Field position", f"{rank} of {rank_total} teams"))
    rows.append(("Checks solved",
                 f"{_solved_count(team.get('checks', []))}"
                 f" of {len(team.get('checks', []))}"))

    for label, value in rows:
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(60, 60, 60)
        pdf.cell(70, 7, text=_ascii(label), new_x=XPos.LMARGIN)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(20, 20, 20)
        pdf.cell(0, 7, text=_ascii(str(value)), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)


def _detail_section(pdf: FPDF, digest: dict) -> None:
    checks, services, incidents = _digest_facts(digest)
    if services:
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 8, text=_ascii("Service uptime"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        for svc in services:
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(60, 60, 60)
            ticks = " ".join(
                "U" if str(t).upper() == "UP" else "D"
                for t in (svc.get("recent_ticks") or [])
            )
            line = (f"{svc.get('check_id')}: {svc.get('state')} at the end,"
                    f" {svc.get('accrued_points')} pts accrued"
                    f" (recent ticks: {ticks})")
            pdf.multi_cell(0, 6, text=_ascii(line),
                           new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    if incidents:
        pdf.ln(6)
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 8, text=_ascii("Red-team events"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        for ev in incidents:
            flag = "recovered" if ev.get("restored") else "not restored"
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(60, 60, 60)
            pdf.multi_cell(
                0, 6, text=_ascii(f"  - {ev.get('event_id')}: handled as {flag}."),
                new_x=XPos.LMARGIN, new_y=YPos.NEXT,
            )
    pdf.ln(2)


def _narrative_section(pdf: FPDF, digest: dict) -> None:
    narration = digest.get("narration") or {}
    headline = narration.get("headline")
    summary = narration.get("summary")
    if headline:
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(20, 20, 20)
        pdf.cell(0, 9, text=_ascii(headline), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(2)

    if summary:
        _heading(pdf, "What happened")
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(40, 40, 40)
        pdf.multi_cell(0, 6, text=_ascii(summary), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

    assessment = narration.get("assessment")
    if assessment:
        _heading(pdf, "Strengths this run")
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(40, 40, 40)
        pdf.multi_cell(0, 6, text=_ascii(assessment),
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)

    why = narration.get("why_matters") or []
    if why:
        _heading(pdf, "Why these mattered")
        for item in why:
            blob = _why_text(item)
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(40, 40, 40)
            pdf.multi_cell(0, 6, text=_ascii("- " + blob), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(2)

    focus = narration.get("focus") or []
    if focus:
        _heading(pdf, "What to work on next")
        for line in focus:
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(40, 40, 40)
            pdf.multi_cell(0, 6, text=_ascii("- " + str(line)),
                           new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(2)


# --- helpers ----------------------------------------------------------------


def _digest_facts(digest: dict) -> tuple:
    team = digest.get("team", {})
    return (
        team.get("checks", []),
        team.get("services", []),
        team.get("incidents", []),
    )


def _heading(pdf: FPDF, text: str) -> None:
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 8, text=_ascii(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _why_text(item: dict) -> str:
    label = item.get("id") or ""
    text = item.get("text") or ""
    return f"{label} — {text}" if text else str(label)


def _fmt_num(value) -> str:
    return str(value)


def _solved_count(checks: list) -> int:
    return len([c for c in checks or [] if c.get("solved")])


def _fmt_date(raw: object) -> str:
    if not raw:
        return ""
    try:
        moment = float(raw)
    except (TypeError, ValueError):
        return str(raw)[:16].replace("T", " ")
    from datetime import datetime, timezone

    return datetime.fromtimestamp(moment, tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC")
