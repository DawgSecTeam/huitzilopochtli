"""Post-event answer-key handout generator.

Renders a scenario.yaml into a walkthrough handout that gives away every
point: per check, the player-facing goal plus the authored ``solution``
markdown (spot it -> trace it -> fix it -> confirm it); forensics questions
with their accepted answers. Output is Markdown, plus an optional themed
HTML page sharing the box README's visual language (boxbuilder/mdhtml.py +
agent/report_page.py).

Authoring-side artifact ONLY: nothing here feeds the manifest, the rubric,
or the on-box install set -- the box never sees any of it. The default
output path lives under artifacts/ (gitignored) per the repo's secrets
discipline. Checks whose ``solution`` was never authored still render, with
a visible placeholder, and are reported back to the caller as gaps so
backfill progress is obvious.
"""
import os
import re
import time
from typing import Optional

import yaml

from boxbuilder.mdhtml import markdown_to_html
from boxbuilder.theme import _readme_logo_b64

_PLACEHOLDER = (
    "> *No walkthrough was authored for this one yet. The goal above states "
    "what was scored; ask an instructor for the steps.*"
)


def load_scenario(scenario_path: str) -> dict:
    """Load + validate a scenario YAML exactly as compile would reject it."""
    with open(scenario_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    from authoring.validate import validate_scenario_yaml

    errors = validate_scenario_yaml(data, scenario_path)
    if errors:
        raise ValueError(
            "scenario failed validation:\n  " + "\n  ".join(errors)
        )
    return data


def solution_text(entry: dict) -> str:
    """Normalize the authored ``solution`` (string or list of strings)."""
    sol = entry.get("solution")
    if sol is None:
        return ""
    if isinstance(sol, str):
        return sol.strip()
    return "\n\n".join(s.strip() for s in sol)


def _backtick(value) -> str:
    return "`" + str(value).replace("`", "'") + "`"


def goal_line(check: dict) -> str:
    """Plain-English restatement of the scored (hardened) state.

    Best-effort per check type / matcher shape; the authored walkthrough is
    the detailed story, this is the one-line 'what was scored'. Unknown
    shapes fall back to a generic-but-honest phrasing rather than guessing.
    """
    ctype = check.get("type")
    collect = check.get("collect") or {}
    # expect carries matcher keys plus scoring keys (points/sla); shape-match
    # on the matcher keys only.
    expect = {k: v for k, v in (check.get("expect") or {}).items()
              if k not in ("points", "sla")}
    path = collect.get("path")

    if ctype == "permission":
        if expect.get("mode_at_most") and expect.get("max_mode"):
            return (f"{_backtick(path)} must have mode "
                    f"{_backtick(expect['max_mode'])} or stricter")
        if expect.get("field") == "exists":
            want = "must exist" if expect.get("equals") else "must be gone from disk"
            return f"{_backtick(path)} {want}"
        return f"{_backtick(path)} must have sane ownership and permissions"

    if ctype == "file_regex":
        if len(expect) == 1 and "equals" in expect:
            if expect["equals"] is None:
                return (f"the flagged pattern in {_backtick(path)} must no "
                        f"longer match anything")
            return (f"{_backtick(path)} must set the checked value to "
                    f"{_backtick(expect['equals'])}")
        if len(expect) == 1 and "regex" in expect:
            return (f"{_backtick(path)} must still match its required "
                    f"hardened pattern")
        return f"{_backtick(path)} must look like the hardened state"

    if ctype == "user_group":
        if "user_absent" in expect:
            return f"the {_backtick(expect.get('username'))} account must not exist"
        if "user_present" in expect:
            return f"the {_backtick(expect.get('username'))} account must exist"
        if "group_members_subset_of" in expect:
            allowed = ", ".join(_backtick(a) for a in expect.get("allowed") or [])
            return (f"{_backtick(expect.get('group'))} group membership "
                    f"must be limited to {allowed}")
        return "accounts and groups must match the authorized roster"

    if ctype == "service_state":
        svc = _backtick(collect.get("service"))
        field = expect.get("field")
        if field == "enabled":
            want = ("must be disabled (won't start at boot)" if not expect.get("equals")
                    else "must be enabled (starts at boot)")
            return f"{svc} {want}"
        if field == "active":
            want = ("must be stopped (not running now)" if not expect.get("equals")
                    else "must be running")
            return f"{svc} {want}"
        return f"{svc} must be in the scored state"

    if ctype == "process_state":
        return (f"no process whose command line matches "
                f"{_backtick(collect.get('pattern'))} may be running")

    if ctype == "package":
        pkg = _backtick(collect.get("package"))
        state = expect.get("equals") or expect.get("contains") or ""
        if str(state).lower() in ("absent", "removed", "not-installed"):
            return f"package {pkg} must be removed"
        if str(state).lower() in ("installed", "present"):
            return f"package {pkg} must be installed"
        return f"package {pkg} must be in the scored state"

    if ctype == "command_json":
        script = collect.get("script") or ""
        if "iptables" in script:
            return "the live firewall rules must match the required posture"
        return "the live on-box probe must report the hardened outcome"

    if ctype == "db_query":
        return (f"{_backtick(collect.get('host'))}:"
                f"{_backtick(collect.get('port'))} must stay reachable")

    return "the checked condition must hold"


def scored_on(check: dict) -> str:
    """Where the points live: the file/service/probe the collector examines."""
    collect = check.get("collect") or {}
    expect = check.get("expect") or {}
    ctype = check.get("type")
    if collect.get("path"):
        return _backtick(collect["path"])
    if collect.get("service"):
        return _backtick(collect["service"])
    if collect.get("pattern"):
        return f"process list (pattern {_backtick(collect['pattern'])})"
    if expect.get("username"):
        return f"the {_backtick(expect['username'])} account"
    if expect.get("group"):
        return f"the {_backtick(expect['group'])} group"
    if collect.get("package"):
        return f"package {_backtick(collect['package'])}"
    if collect.get("host") and collect.get("port"):
        return f"{collect['host']}:{collect['port']} reachability"
    return "a live on-box probe"


def _check_body(check: dict, gaps: list, label: str) -> str:
    lines = [
        f"*Goal:* {goal_line(check)}  ",
        f"*Scored on:* {scored_on(check)} · *Worth:* {abs(check.get('max_points', 0))} pts",
        "",
    ]
    sol = solution_text(check)
    if sol:
        lines.append(sol)
    else:
        gaps.append(label)
        lines.append(_PLACEHOLDER)
    return "\n".join(lines)


def render_markdown(scenario: dict, source_path: str) -> tuple:
    """Render the full handout. Returns (markdown_text, gap_labels)."""
    meta = scenario.get("scenario") or {}
    name = meta.get("name") or "Scenario"
    checks = scenario.get("checks") or []
    forensics = scenario.get("forensics") or []
    gaps: list = []

    vulns = [c for c in checks if c.get("category") == "vuln"]
    penalties = [c for c in checks if c.get("category") != "vuln"]
    vuln_pts = sum(c.get("max_points", 0) for c in vulns)
    for_pts = sum(f.get("points", 0) for f in forensics)

    out = []
    out.append(f"# {name} — post-event walkthrough & answer key")
    out.append("")
    out.append(
        "> **Spoiler warning:** this document gives away every point on the "
        "box — how to find each issue, fix it, and the forensics answers. "
        "Hand it out after the event only."
    )
    out.append("")
    out.append(
        f"Scenario version {meta.get('version')} · generated from "
        f"`{source_path}` by `boxbuilder answer-key`."
    )
    out.append("")
    out.append("**How scoring worked.** Challenge checks awarded their points "
               "while the hardened state held — the scoring agent re-checked "
               "the box on every pass, so a fix that got undone stopped "
               "scoring. Forensics questions were graded from your answers "
               "file; a wrong or blank answer cost nothing. Penalties only "
               "ever subtracted.")
    out.append("")
    out.append(f"## The challenges ({len(vulns)} checks · {vuln_pts} points)")
    out.append("")
    for c in vulns:
        label = c.get("display") or c.get("id")
        out.append(f"### {label} · {c.get('max_points')} pts")
        out.append("")
        out.append(_check_body(c, gaps, label))
        out.append("")

    if penalties:
        pen_pts = sum(abs(c.get("max_points", 0)) for c in penalties)
        out.append(f"## Watch your step ({len(penalties)} penalty "
                   f"check{'s' if len(penalties) != 1 else ''} · up to "
                   f"{pen_pts} points subtracted)")
        out.append("")
        for c in penalties:
            label = c.get("display") or c.get("id")
            out.append(f"### {label} · −{abs(c.get('max_points', 0))} pts when triggered")
            out.append("")
            out.append(_check_body(c, gaps, label))
            out.append("")

    out.append(f"## Forensics questions ({len(forensics)} questions · "
               f"{for_pts} points)")
    out.append("")
    for i, fq in enumerate(forensics, 1):
        out.append(f"### Q{i}. {fq.get('question')} · {fq.get('points')} pts")
        out.append("")
        answers = []
        if fq.get("answer"):
            answers.append(fq["answer"])
        answers.extend(fq.get("answers") or [])
        if answers:
            shown = " or ".join(_backtick(a) for a in answers)
            out.append(f"**Accepted answer{'s' if len(answers) > 1 else ''}:** {shown}")
            out.append("")
        sol = solution_text(fq)
        if sol:
            out.append("**How to find it.**")
            out.append("")
            out.append(sol)
        elif fq.get("path"):
            gaps.append(f"Q{i} ({fq.get('id')})")
            out.append(f"**How to find it.** The evidence lives under "
                       f"{_backtick(fq['path'])}.")
            out.append("")
            out.append(_PLACEHOLDER)
        else:
            gaps.append(f"Q{i} ({fq.get('id')})")
            out.append(_PLACEHOLDER)
        out.append("")

    out.append("---")
    out.append("")
    out.append(f"*Generated {time.strftime('%Y-%m-%d %H:%M')} by "
               f"`boxbuilder answer-key` from `{source_path}` "
               f"(scenario v{meta.get('version')}).*")
    return "\n".join(out), gaps


def render_html(markdown_text: str, scenario: dict, base_dir: str) -> str:
    """Themed standalone HTML page in the box README's visual language."""
    from agent.report_page import accent_css, masthead_html, page_shell

    theme = scenario.get("theme") or {}
    title = str(theme.get("title") or "Answer Key")
    logo_b64 = _readme_logo_b64(theme, base_dir)
    body = (
        f"{masthead_html(title, theme.get('organization'), logo_b64)}\n"
        f'<div class="prose">\n{markdown_to_html(markdown_text)}\n</div>'
    )
    return page_shell(f"{title} — Answer Key", body, accent=accent_css(theme.get("accent")))


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "scenario"


def generate(scenario_path: str, out_path: Optional[str] = None,
             want_html: bool = False) -> dict:
    """Render + write the handout. Returns a summary dict for the CLI.

    Default output: artifacts/answer-keys/<scenario-slug>.md (gitignored),
    with the HTML page (when --html) written next to it as <slug>.html.
    """
    scenario_path = os.path.abspath(scenario_path)
    scenario = load_scenario(scenario_path)
    markdown_text, gaps = render_markdown(scenario, scenario_path)

    if out_path is None:
        name = (scenario.get("scenario") or {}).get("name") or "scenario"
        out_path = os.path.join("artifacts", "answer-keys", f"{_slug(name)}.md")
    out_path = os.path.abspath(out_path)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(markdown_text + "\n")

    result = {
        "ok": True,
        "markdown": out_path,
        "missing_walkthroughs": gaps,
        "checks": len(scenario.get("checks") or []),
        "forensics": len(scenario.get("forensics") or []),
    }

    if want_html:
        html_path = os.path.splitext(out_path)[0] + ".html"
        page = render_html(markdown_text, scenario, os.path.dirname(scenario_path))
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(page)
        result["html"] = html_path

    if gaps:
        # Progress surface, not a failure: the handout is still written.
        result["note"] = (
            f"{len(gaps)} item(s) have no authored walkthrough yet: "
            + "; ".join(gaps)
        )
    return result
