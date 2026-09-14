"""huitz — the native terminal experience for a scored box.

The terminal twin of the Desktop report.html: same data, same moment, same
design language (flat "paper" surfaces, one theme accent, semantic green/red)
rendered idiomatically for a terminal instead of ported from the web page.

    huitz score              one-shot scorecard
    huitz watch              live frame: countdown, updates, change bell
    huitz forensics          forensics questions: list, answer, re-answer
    huitz grade              re-grade right now (root, honor boxes)
    huitz help

Data source: agent/snapshot.py's report.json, published by the agent on
every grade and Desktop-mirrored by packaging/sync-report.sh — so every
command works as ANY user on the box, no root and no sealed-dir access
needed (except `grade`, which runs the scoring pipeline and therefore
requires root, exactly like the systemd timer does).

Honor mode renders the CyberPatriot-style board (positive-only: failed
checks stay anonymous, both here and in the snapshot, so the CLI can't
leak what the HTML doesn't). Ranked mode renders the engine's diagnostic
view (per-check results + SLA), mirroring the ranked HTML table — the
rubric never shipped to this box, so there is nothing to leak.

Pure stdlib; terminal behavior lives in agent/term.py. Only `grade`
touches the scoring pipeline (via agent/__main__), and only for honor
mode — ranked grading is the engine's job (§13).
"""
import json
import os
import re
import sys
import time

import agent.answers
import agent.snapshot
import agent.term
from agent.term import Symbols, Style

VERBS = ("score", "grade", "watch", "forensics", "readme", "help")

USAGE = """huitz — scoring console for this Huitzilopochtli box

usage:
  huitz score                    show the current scorecard
  huitz score --json             ... as raw JSON (the report.json snapshot)
  huitz watch                    live scorecard: countdown, updates, bell
  huitz watch --once             render one frame and exit
  huitz readme                   the scenario handbook, in the terminal
  huitz readme --raw             ... as raw markdown
  huitz forensics                list forensics questions + your answers
  huitz forensics N "answer"     answer question N (interactive if TEXT omitted)
  huitz grade                    re-grade right now (root; honor boxes)

options:
  --report PATH   snapshot to read (default: auto-discover, install dir first)
  --answers PATH  forensics answers file (default: the one the snapshot names)
  --config PATH   grade: agent_config.json (default: this box's install dir)
  --color WHEN    auto | always | never   (NO_COLOR is always honored)
  --json          score: print the raw snapshot
  --quiet         grade: print one summary line instead of the board

`huitz` reads the same grade the Desktop report.html shows — nothing here
re-scores the box except `grade`, which is the timer's work done on demand."""

DEFAULT_CONFIGS = {
    "posix": "/opt/.huitzilopochtli/agent_config.json",
    "nt": r"C:\ProgramData\huitzilopochtli\agent_config.json",
}
DEFAULT_REPORT_JSON = {
    "posix": "/opt/.huitzilopochtli/report.json",
    "nt": r"C:\ProgramData\huitzilopochtli\report.json",
}
ENV_REPORT = "HUITZ_REPORT"      # pin a snapshot explicitly (docs/testing)
ENV_CONFIG = "HUITZ_CONFIG"      # pin an agent config for `grade`

_EXIT_OK, EXIT_ERROR, _EXIT_USAGE = 0, 1, 2


class UsageError(Exception):
    """Bad arguments — prints usage guidance, exit code 2."""


class CliError(Exception):
    """User-facing failure — message printed verbatim, exit code 1."""


# --- argument plumbing --------------------------------------------------------

def _split_flags(argv: list, bool_flags: set, val_flags: set) -> tuple:
    """Return (positional, opts). Flags may appear anywhere; `--flag value`
    and `--flag=value` both parse; unknown flags are a UsageError."""
    positional, opts = [], {}
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in bool_flags:
            opts[arg] = True
        elif arg in val_flags:
            if i + 1 >= len(argv):
                raise UsageError(f"{arg} needs a value")
            opts[arg] = argv[i + 1]
            i += 1
        elif arg.startswith("--") and "=" in arg:
            name, _, value = arg.partition("=")
            if name in bool_flags:
                opts[name] = True
            elif name in val_flags:
                opts[name] = value
            else:
                raise UsageError(f"unknown option {name}")
        else:
            positional.append(arg)
        i += 1
    return positional, opts


def _color_override(opts: dict) -> str:
    when = opts.get("--color", "auto").lower()
    if when not in ("auto", "always", "never"):
        raise UsageError(f"--color must be auto|always|never, not {when!r}")
    return when


def _make_style(opts: dict, stream, snapshot: dict | None = None) -> Style:
    accent = (snapshot or {}).get("accent")
    if accent and not str(accent).startswith("#"):
        accent = None
    return agent.term.Style.detect(stream, _color_override(opts), accent=accent)


# --- snapshot discovery --------------------------------------------------------

def _install_config_path() -> str:
    return os.environ.get(ENV_CONFIG) or DEFAULT_CONFIGS["nt" if os.name == "nt" else "posix"]


def _report_json_from_config(config_path: str) -> str | None:
    """report.json path from a readable agent_config.json, else the known
    install-dir default (root can read the sealed dir even when the config
    parse is unnecessary — the known path is the same file)."""
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            report_path = json.load(f).get("report_path")
        if report_path:
            return agent.snapshot.snapshot_path_for(report_path)
    except (OSError, ValueError):
        pass
    return DEFAULT_REPORT_JSON["nt" if os.name == "nt" else "posix"]


def _desktop_report_paths() -> list:
    """Desktop report.json candidates, this user first, then other real
    accounts (the uid 1000-59999 + login-shell heuristic that sync-report.sh
    and agent/notify.py use)."""
    out = []
    home = os.path.expanduser("~")
    if os.name == "nt":
        public_desktop = os.path.join(
            os.environ.get("PUBLIC", r"C:\Users\Public"), "Desktop")
        out.append(os.path.join(public_desktop, "report.json"))
        out.append(os.path.join(home, "Desktop", "report.json"))
        return out
    out.append(os.path.join(home, "Desktop", "report.json"))
    seen = {out[0]}
    try:
        import pwd
        for entry in pwd.getpwall():
            if entry.pw_uid < 1000 or entry.pw_uid >= 60000:
                continue
            shell = entry.pw_shell or ""
            if shell.endswith("/nologin") or shell.endswith("/false"):
                continue
            candidate = os.path.join(entry.pw_dir, "Desktop", "report.json")
            if candidate not in seen:
                seen.add(candidate)
                out.append(candidate)
    except ImportError:
        pass
    return out


def locate_snapshot(explicit: str | None = None) -> tuple:
    """Return (path_or_None, searched). With `explicit`, that path is the
    only candidate; otherwise: $HUITZ_REPORT, the install dir (root path),
    then Desktop copies (any user's)."""
    if explicit:
        if os.path.isdir(explicit):
            explicit = os.path.join(explicit, "report.json")
        elif os.path.basename(explicit).endswith(".html"):
            explicit = agent.snapshot.snapshot_path_for(explicit)
        return (explicit if os.path.isfile(explicit) else None), [explicit]

    candidates = []
    env = os.environ.get(ENV_REPORT)
    if env:
        candidates.append(env)
    candidates.append(_report_json_from_config(_install_config_path()))
    candidates.extend(_desktop_report_paths())

    searched = []
    for candidate in candidates:
        if candidate in searched:
            continue
        searched.append(candidate)
        if os.path.isfile(candidate):
            return candidate, searched
    return None, searched


def _load_snapshot(explicit: str | None) -> dict:
    path, searched = locate_snapshot(explicit)
    if path is None:
        detail = f" (looked in: {', '.join(searched)})" if searched else ""
        raise CliError(
            "no grade found on this box yet — no report snapshot" + detail + ".\n"
            "Run `sudo huitz grade` (honor) or wait for the re-grade timer / "
            "next engine check-in."
        )
    try:
        return agent.snapshot.read(path)
    except agent.snapshot.SnapshotError as e:
        raise CliError(str(e)) from e


# --- formatting helpers ---------------------------------------------------------

def _fmt_utc(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))


def _fmt_clock(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.gmtime(ts))


def _pts_cell(sty: Style, points: int) -> str:
    if points > 0:
        return sty.color(f"+{points}", "ok", 1)
    if points < 0:
        return sty.color(str(points), "bad", 1)
    return sty.color("0", "muted")


def _pts_plain(points: int) -> str:
    return f"+{points}" if points > 0 else str(points)


def _leader_line(sty: Style, sym: Symbols, title: str, right_plain: str,
                 right_styled: str, width: int, indent: int = 4) -> str:
    """`title .......... right` with dot leaders filling to `width`.

    Width math uses visible lengths only (`right_styled` may carry SGR)."""
    lead_width = (width - indent - agent.term.visible_len(title)
                  - len(right_plain) - 2)
    if lead_width < 3:
        return agent.term.truncate_ansi(
            " " * indent + title + "  " + right_styled, width)
    fill = "·" if sym.utf8 else "."
    leader = " " + (fill * lead_width) + " "
    return " " * indent + title + sty.color(leader, "muted") + right_styled


# --- scorecard rendering ---------------------------------------------------------

def render_scorecard(snap: dict, sty: Style, sym: Symbols, width: int,
                     now: float | None = None, hints: bool = False) -> str:
    """The full frame. Pure: takes the snapshot dict + style, returns text
    clipped to `width` (styling is ANSI-safe to cut — see truncate_ansi)."""
    now = time.time() if now is None else now
    mode = snap.get("mode", "honor")
    lines = []

    # masthead — same information architecture as the HTML report
    title = str(snap.get("title") or snap.get("scenario_name") or "Score report")
    lines.append(sty.color(sty.bold(title), "accent"))
    sub = [f"scenario v{snap.get('scenario_version', '?')}", f"{mode} mode"]
    if snap.get("organization"):
        sub.append(str(snap["organization"]))
    lines.append(sty.color("  ·  ".join(sub), "muted"))
    lines.append(sty.color(agent.term.rule(min(width, 78), sym), "accent"))
    lines.append("")

    if snap.get("awaiting_engine"):
        lines.append(sty.color("  submitted — awaiting engine", 1))
        lines.append("")
        lines.append(sty.color(
            "  The engine has not confirmed a check-in from this box yet.",
            "muted"))
        lines.append(sty.color(
            "  This view updates the moment the first score arrives.",
            "muted"))
        return "\n".join(agent.term.truncate_ansi(l, width) for l in lines)

    total = snap.get("total") or 0
    pct = int(snap.get("progress_pct") or 0)

    # total + progress. The total stands alone (forensics points are part of
    # it but not of the vuln-check max, so "total / max" would mislead — the
    # bar row carries progress context instead).
    lines.append("  " + sty.color(sty.bold(f"{total} pts"), "accent"))
    bar_width = min(31, max(9, width - 42))
    bar = agent.term.progress_bar(pct, bar_width, sym)
    row = f"  {sty.color(bar, 'accent')} {pct:3d}%"
    if mode == "honor":
        counts = (f"{snap.get('vulns_fixed', 0)} of {snap.get('vulns_total', 0)}"
                  " fixed")
        row += sty.color(f"  ·  {counts}", "muted")
        remaining = int(snap.get("remaining") or 0)
        if remaining:
            row += sty.color(f"  ·  {remaining} issue(s) remain", "muted")
    else:
        row += "  " + sty.color("the engine's authoritative score", "muted")
    lines.append(row)
    lines.append("")

    if mode == "honor":
        lines.extend(_board_sections(snap, sty, sym, width))
    else:
        lines.extend(_ranked_sections(snap, sty, sym, width))
        lines.append("")

    # delta banner — same one-run semantics as the HTML (nonzero only on the
    # grade right after the change)
    delta = snap.get("delta")
    if isinstance(delta, int) and not isinstance(delta, bool) and delta != 0:
        lines.append("")
        if delta > 0:
            lines.append("  " + sty.color(
                f"{sym.up} +{delta} pts since the last grading pass", "ok", 1))
        else:
            lines.append("  " + sty.color(
                f"{sym.down} {delta} pts — penalty: a scored setting was "
                "undone or a new issue introduced", "bad", 1))

    # footer stamps
    stamps = []
    computed_at = snap.get("computed_at")
    if computed_at:
        stamps.append(f"last graded {_fmt_clock(computed_at)} UTC"
                      if mode == "honor" else
                      f"last confirmed {_fmt_clock(computed_at)} UTC")
    next_at = snap.get("next_event_at")
    if next_at:
        remaining_s = float(next_at) - now
        label = "next re-grade" if mode == "honor" else "next check-in"
        if remaining_s > 0:
            stamps.append(f"{label} ~{agent.term.fmt_mmss(remaining_s)}")
        elif -remaining_s > _OVERDUE_NOTE_AFTER_S:
            # Kept short: the footer shares a line with the last-graded stamp.
            stamps.append(f"{label} overdue by {agent.term.fmt_mmss(-remaining_s)}"
                          " (timer stalled?)")
        else:
            stamps.append(f"{label} due now")
    if stamps:
        lines.append("")
        lines.append("  " + sty.color("  ·  ".join(stamps), "muted"))
    if hints:
        lines.append(sty.color(
            "  try: huitz watch  ·  huitz forensics  ·  huitz grade", 2))
    return "\n".join(agent.term.truncate_ansi(l, width) for l in lines)


def _board_sections(snap: dict, sty: Style, sym: Symbols, width: int) -> list:
    """Honor board: fixed vulns, penalties, forensics (positive-only)."""
    lines = []

    fixed = snap.get("fixed") or []
    header = (f"{sty.color(sym.check, 'ok', 1)} "
              + sty.bold(f"VULNERABILITIES FIXED — {snap.get('vulns_fixed', 0)}"
                         f" of {snap.get('vulns_total', 0)}"))
    lines.append("  " + header)
    if fixed:
        for v in fixed:
            points = int(v.get("points", 0))
            lines.append(_leader_line(sty, sym, str(v.get("title", "?")),
                                      _pts_plain(points), _pts_cell(sty, points),
                                      width))
    else:
        lines.append("      " + sty.color("no vulnerabilities fixed yet", "muted"))
    if snap.get("all_fixed"):
        lines.append("      " + sty.color(sym.check + " all scored issues fixed",
                                          "ok"))
    lines.append("")

    penalties = snap.get("penalties") or []
    header = (f"{sty.color('!', 'warn', 1)} "
              + sty.bold(f"PENALTIES — {len(penalties)}"))
    lines.append("  " + header)
    if penalties:
        for p in penalties:
            points = int(p.get("points", 0))
            lines.append(_leader_line(sty, sym, str(p.get("title", "?")),
                                      _pts_plain(points), _pts_cell(sty, points),
                                      width))
    else:
        lines.append("      " + sty.color("none", "muted"))
    lines.append("")

    forensics = snap.get("forensics") or []
    if forensics:
        earned = int(snap.get("forensics_earned") or 0)
        lines.append("  " + sty.bold(f"FORENSICS — {earned} of {len(forensics)}"))
        for f in forensics:
            mark = (sty.color(sym.check, "ok", 1) if f.get("answered")
                    else sty.color(sym.bullet, "muted"))
            points = int(f.get("points", 0))
            pts_plain = _pts_plain(points) if f.get("answered") else "0"
            pts_styled = (_pts_cell(sty, points) if f.get("answered")
                          else sty.color("0", "muted"))
            title = f"Q{f.get('ordinal') or '?'} {f.get('question', '')}"
            lines.append(_leader_line(sty, sym, f"{mark} {title}",
                                      pts_plain, pts_styled, width, indent=4))
        answers_paths = sorted({f.get("answers_path") for f in forensics
                                if f.get("answers_path")})
        if answers_paths:
            lines.append("      " + sty.color(
                f"answers: {answers_paths[0]}", "muted"))
    return lines


def _ranked_sections(snap: dict, sty: Style, sym: Symbols, width: int) -> list:
    """Ranked diagnostic view: per-check results + SLA — mirrors the ranked
    HTML table (safe on-box: the rubric never shipped here)."""
    lines = []
    results = snap.get("results") or []
    lines.append("  " + sty.bold("CHECK RESULTS"))
    if results:
        id_w = max(8, min(30, max(len(r.get("check_id", "")) for r in results)))
        pts_w = 5
        head = (f"  {'CHECK':<{id_w}}  {'CATEGORY':<10} {'PTS':>{pts_w}}  DETAIL")
        lines.append(sty.color(head, 1))
        lines.append(sty.color(agent.term.rule(min(width, 78) - 2, sym), "muted"))
        for r in results:
            cid = agent.term.ellipsize(str(r.get("check_id", "")), id_w, sym)
            cat = agent.term.ellipsize(str(r.get("category", "")), 10, sym)
            points = int(r.get("awarded_points", 0))
            plain = _pts_plain(points)
            reason_width = max(8, width - (id_w + 10 + pts_w + 8))
            reason = agent.term.ellipsize(str(r.get("reason", "")), reason_width, sym)
            pad = " " * (pts_w - len(plain))
            lines.append(
                f"  {cid:<{id_w}}  {sty.color(cat, 'muted')} {pad}"
                f"{_pts_cell(sty, points)}  {sty.color(reason, 'muted')}")
    else:
        lines.append("      " + sty.color("no point-in-time checks", "muted"))

    sla = snap.get("sla_status") or []
    if sla:
        lines.append("")
        lines.append("  " + sty.bold("SLA STATUS"))
        for s in sla:
            state = str(s.get("state", "?")).upper()
            colored = (sty.color(state, "ok", 1) if state == "UP"
                       else sty.color(state, "bad", 1))
            cid = agent.term.ellipsize(str(s.get("check_id", "")), 30, sym)
            lines.append(
                f"  {cid:<30}  {colored}  "
                + sty.color(f"accrued {s.get('accrued_points', 0)}", "muted"))
    return lines


# --- forensics -------------------------------------------------------------------

def _default_answers_path() -> str:
    if os.name == "nt":
        return os.path.join(
            os.environ.get("PUBLIC", r"C:\Users\Public"), "Desktop",
            "Forensics-Questions.txt")
    return os.path.join(os.path.expanduser("~"), "Desktop",
                        "Forensics-Questions.txt")


def _display_answer(content: str, ordinal: int) -> str | None:
    """The team's answer as the CLI should show it: an untouched underscore
    placeholder reads as blank."""
    answer, _found = agent.answers.extract_answer(content, ordinal)
    if answer and agent.answers.ANSWER_PLACEHOLDER_RE.match(answer):
        return None
    return answer


def _forensics_entries(snap: dict) -> list:
    entries = sorted(snap.get("forensics") or [],
                     key=lambda f: (f.get("ordinal") or 0, str(f.get("id"))))
    return entries


def _entry_ordinal(entry: dict, index: int) -> int:
    return int(entry.get("ordinal") or 0) or (index + 1)


def _write_answers_file(path: str, content: str) -> None:
    """Replace the answers file, preserving mode + ownership (root editing a
    user's file must not seize it)."""
    try:
        st = os.stat(path)
        mode, uid, gid = st.st_mode & 0o7777, st.st_uid, st.st_gid
    except OSError:
        mode = uid = gid = None
    tmp = path + ".huitz-tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
    if mode is not None:
        try:
            os.chmod(tmp, mode)
            if uid is not None and (uid != os.geteuid() if hasattr(os, "geteuid") else True):
                os.chown(tmp, uid, gid)
        except OSError:
            pass
    else:
        try:
            os.chmod(tmp, 0o666)  # match agent/__main__'s template: team-editable
        except OSError:
            pass
    os.rename(tmp, path)


def _ensure_answers_file(path: str, entries: list) -> None:
    if os.path.exists(path):
        return
    questions = [
        (_entry_ordinal(e, i), str(e.get("question", "")))
        for i, e in enumerate(entries)
    ]
    _write_answers_file(path, agent.answers.render_template(questions))


def _read_answers(path: str) -> str:
    with open(path, "r", errors="replace") as f:
        return f.read(agent.answers.CONTENT_LIMIT)


def _answer_status(entry: dict, current: str | None) -> tuple:
    """(label, styled) describing the relationship between the file's current
    answer and the last grade's verdict."""
    if current:
        if entry.get("answered"):
            return "recorded", None
        return "recorded — awaiting re-grade", "muted"
    if entry.get("answered"):
        return "answered on the last grade; the file is now blank", "warn"
    return "blank", "muted"


def render_forensics(snap: dict, sty: Style, sym: Symbols, width: int,
                     answers_override: str | None) -> str:
    entries = _forensics_entries(snap)
    if not entries:
        return sty.color("This scenario has no forensics questions.", "muted")

    paths = {e.get("answers_path") for e in entries if e.get("answers_path")}
    default_path = answers_override or (paths.pop() if len(paths) == 1 else None) \
        or _default_answers_path()

    lines = ["  " + sty.bold(
        f"FORENSICS — {snap.get('forensics_earned', 0)} of {len(entries)}")]
    lines.append("      " + sty.color(f"answers file: {default_path}", "muted"))
    lines.append("")

    current_by_ordinal = {}
    try:
        content = _read_answers(default_path)
        for i in range(len(entries)):
            current_by_ordinal[i] = _display_answer(content, _entry_ordinal(entries[i], i))
    except OSError:
        for i in range(len(entries)):
            current_by_ordinal[i] = None

    for i, e in enumerate(entries):
        ordinal = _entry_ordinal(e, i)
        mark = (sty.color(sym.check, "ok", 1) if e.get("answered")
                else sty.color(sym.bullet, "muted"))
        pts = (_pts_cell(sty, int(e.get("points", 0))) if e.get("answered")
               else sty.color(f"0/{e.get('max_points', 0)}", "muted"))
        question = agent.term.ellipsize(str(e.get("question", "")),
                                        max(20, width - 24), sym)
        lines.append(f"  {mark} Q{ordinal}  {question}  {pts}")
        current = current_by_ordinal.get(i)
        if current:
            shown = agent.term.ellipsize(f'"{current}"', max(20, width - 12), sym)
            lines.append("         " + sty.color(f"your answer: {shown}", "ink"))
        else:
            lines.append("         " + sty.color("your answer: (blank)", "muted"))
        label, tone = _answer_status(e, current)
        lines.append("         " + sty.color(label, tone) if tone else
                     "         " + sty.color(label, "muted"))

    lines.append("")
    lines.append(sty.color(
        '  set an answer:  huitz forensics N "your answer"   '
        "(or just: huitz forensics N)", 2))
    lines.append(sty.color(
        "  answers re-grade automatically (about a minute), or: sudo huitz grade", 2))
    return "\n".join(lines)


def set_forensics_answer(snap: dict, ordinal: int, text: str | None,
                         answers_override: str | None,
                         instream, outstream) -> int:
    """Answer question `ordinal`. text=None means interactive prompt.
    Returns an exit code."""
    entries = _forensics_entries(snap)
    index = next((i for i, e in enumerate(entries)
                  if _entry_ordinal(e, i) == ordinal), None)
    if index is None:
        valid = ", ".join(str(_entry_ordinal(e, i))
                          for i, e in enumerate(entries)) or "none"
        raise CliError(f"no forensics question {ordinal} (have: {valid})")
    entry = entries[index]

    paths = {e.get("answers_path") for e in entries if e.get("answers_path")}
    path = answers_override or (paths.pop() if len(paths) == 1 else None) \
        or _default_answers_path()

    _ensure_answers_file(path, entries)
    content = _read_answers(path)
    current = _display_answer(content, ordinal)

    if text is None:
        if not agent.term.is_interactive(instream):
            raise CliError(
                "no answer text given and stdin is not a terminal — "
                f'pass it instead: huitz forensics {ordinal} "your answer"')
        q = agent.term.ellipsize(str(entry.get("question", "")), 70, Symbols(True))
        print(f"Q{ordinal}: {q}", file=outstream)
        print(f"current: {current or '(blank)'}", file=outstream)
        print("new answer (Enter keeps current, '-' clears): ",
              end="", file=outstream, flush=True)
        try:
            text = instream.readline().rstrip("\r\n")
        except (EOFError, KeyboardInterrupt):
            print("\nunchanged.", file=outstream)
            return _EXIT_OK
        if text == "":
            print("unchanged.", file=outstream)
            return _EXIT_OK
    if text == "-":
        # "-" means clear, interactively or scripted.
        text = ""

    new_content, found = agent.answers.set_answer(content, ordinal, text)
    if not found:
        raise CliError(
            f"{path} has no Q{ordinal} block to answer into — it may have been "
            "edited by hand; restore the template or use --answers PATH")
    try:
        _write_answers_file(path, new_content)
    except OSError as e:
        raise CliError(f"could not write {path}: {e}") from e

    sym = Symbols(True)
    if text:
        print(f"{sym.check} Q{ordinal} answered: \"{text}\"", file=outstream)
    else:
        print(f"Q{ordinal} cleared.", file=outstream)
    print("It scores on the next re-grade (about a minute), or: sudo huitz grade",
          file=outstream)
    return _EXIT_OK


# --- readme (the scenario handbook) ------------------------------------------------

_INLINE_BOLD_RE = re.compile(r"\*\*(.+?)\*\*")
_INLINE_CODE_RE = re.compile(r"`([^`]+)`")
_INLINE_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")
_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
_LIST_RE = re.compile(r"^[-*]\s+(.*)$")
_ORDERED_RE = re.compile(r"^(\d+[.)])\s+(.*)$")


def _inline(text: str, sty: Style) -> str:
    """One markdown line rendered for the terminal: **bold** to bold,
    `code` to dim, [text](url) to text <url>. Line length is left to the
    terminal (the readme is a static page, not a live frame)."""
    text = _INLINE_LINK_RE.sub(lambda m: f"{m.group(1)} <{m.group(2)}>", text)
    parts = []
    pos = 0
    for m in _INLINE_BOLD_RE.finditer(text):
        parts.append(text[pos:m.start()])
        parts.append(sty.bold(m.group(1)))
        pos = m.end()
    parts.append(text[pos:])
    text = "".join(parts)
    text = _INLINE_CODE_RE.sub(lambda m: sty.color(m.group(1), "muted"), text)
    return text


def render_readme(text: str, sty: Style, sym: Symbols, width: int) -> str:
    """The handbook, typeset for a terminal. Deliberately small: headings,
    lists, quotes, fenced blocks, rules, inline emphasis. Anything fancier
    stays in the themed README.html on desktop boxes — the terminal view
    must stay readable in plain ASCII too."""
    out = []
    in_fence = False
    for raw in text.splitlines():
        if raw.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            out.append("  " + sty.color(
                agent.term.ellipsize(raw, max(20, width - 4), sym), "muted"))
            continue
        stripped = raw.strip()
        if not stripped:
            out.append("")
            continue
        if stripped in ("---", "***", "___"):
            out.append(sty.color(agent.term.rule(min(width, 78), sym), "muted"))
            continue
        m = _HEADING_RE.match(stripped)
        if m:
            level, head = len(m.group(1)), _inline(m.group(2), sty)
            if level == 1:
                out.append(sty.color(sty.bold(head), "accent"))
                out.append(sty.color(agent.term.rule(min(width, 78), sym),
                                     "accent"))
            elif level == 2:
                out.append(sty.bold(head))
                out.append(sty.color(
                    agent.term.rule(min(width, len(m.group(2)) + 2), sym),
                    "muted"))
            else:
                out.append(sty.bold(head))
            continue
        m = _LIST_RE.match(stripped)
        if m:
            out.append("  " + sty.color(sym.bullet, "muted") + " "
                       + _inline(m.group(1), sty))
            continue
        m = _ORDERED_RE.match(stripped)
        if m:
            out.append("  " + sty.color(m.group(1), "muted") + " "
                       + _inline(m.group(2), sty))
            continue
        if stripped.startswith(">"):
            out.append("  " + sty.color(
                _inline(stripped.lstrip("> ").strip(), sty), "muted"))
            continue
        out.append(_inline(stripped, sty))
    return "\n".join(out)


def cmd_readme(argv: list, outstream) -> int:
    positional, opts = _split_flags(argv, {"--raw"}, {"--report", "--color"})
    if positional:
        raise UsageError(f"readme takes no arguments (got {positional[0]!r})")
    snap = _load_snapshot(opts.get("--report"))
    text = snap.get("readme")
    if not text or not isinstance(text, str):
        raise CliError(
            "this scenario ships no handbook (no theme.readme in the "
            "scenario) — ask the scenario author to add one")
    if opts.get("--raw"):
        outstream.write(text if text.endswith("\n") else text + "\n")
        return _EXIT_OK
    sty = _make_style(opts, outstream, snap)
    sym = Symbols(sty.utf8)
    width = agent.term.detect_width(outstream)
    for line in render_readme(text, sty, sym, width).splitlines():
        print(line, file=outstream)
    return _EXIT_OK


# --- commands ---------------------------------------------------------------------

def cmd_score(argv: list, outstream) -> int:
    positional, opts = _split_flags(
        argv, {"--json", "--quiet"}, {"--report", "--color"})
    if positional:
        raise UsageError(f"score takes no arguments (got {positional[0]!r})")
    snap = _load_snapshot(opts.get("--report"))

    if opts.get("--json"):
        json.dump(snap, outstream, indent=1)
        outstream.write("\n")
        return _EXIT_OK

    sty = _make_style(opts, outstream, snap)
    sym = Symbols(sty.utf8)
    width = agent.term.detect_width(outstream)
    frame = render_scorecard(snap, sty, sym, width, hints=True)
    for line in frame.splitlines():
        print(agent.term.truncate_ansi(line, width), file=outstream)
    return _EXIT_OK


def cmd_watch(argv: list, outstream, instream) -> int:
    positional, opts = _split_flags(
        argv, {"--once"}, {"--report", "--color"})
    if positional:
        raise UsageError(f"watch takes no arguments (got {positional[0]!r})")
    sty = _make_style(opts, outstream)
    sym = Symbols(sty.utf8)
    snap_path, searched = locate_snapshot(opts.get("--report"))
    if snap_path is None:
        raise CliError(
            "nothing to watch yet — no report snapshot found"
            + (f" (looked in: {', '.join(searched)})" if searched else "")
            + ".\nGrade first: sudo huitz grade (honor) or wait for the "
            "timer / engine check-in.")

    interactive = (agent.term.is_interactive(outstream)
                   and agent.term.is_interactive(instream))
    forced_once = bool(opts.get("--once"))
    once = forced_once or not interactive
    if not interactive and not forced_once:
        print("huitz watch: stdin/stdout is not a terminal; rendering one "
              "frame (use --once to silence this note).", file=outstream)

    poller = agent.term.KeyPoller(None if once else instream)
    raw_bytes = None        # last seen snapshot file content
    last_snap = None        # last successfully parsed snapshot
    session_log = []        # [(wallclock, delta)] — changes seen while watching
    try:
        while True:
            now = time.time()
            error_note = None
            rang_bell = False
            try:
                with open(snap_path, "rb") as f:
                    current = f.read()
                if current != raw_bytes:
                    is_regrade = raw_bytes is not None
                    raw_bytes = current
                    last_snap = agent.snapshot.read(snap_path)
                    delta = last_snap.get("delta")
                    if is_regrade and isinstance(delta, int) \
                            and not isinstance(delta, bool) and delta != 0:
                        # Only changes observed *while watching* ring the
                        # bell and log; a pre-existing banner is old news.
                        session_log.append((now, delta))
                        session_log[:] = session_log[-5:]
                        rang_bell = True
            except agent.snapshot.SnapshotError as e:
                error_note = str(e)
            except OSError:
                error_note = f"snapshot vanished: {snap_path}"

            width = agent.term.detect_width(outstream)
            if last_snap is not None:
                frame = render_scorecard(last_snap, sty, sym, width, now=now,
                                         hints=once)
            elif error_note:
                if once:
                    raise CliError(error_note)
                frame = sty.color("  " + error_note, "warn")
            else:
                frame = sty.color("  waiting for a grade…", "muted")

            if session_log:
                frame += "\n" + sty.color("  this session:", "muted")
                for ts, d in session_log:
                    arrow = f"{sym.up} +{d}" if d > 0 else f"{sym.down} {d}"
                    frame += "\n    " + sty.color(
                        f"{_fmt_clock(ts)}  {arrow} pts",
                        "ok" if d > 0 else "bad")
            if not once:
                countdown = _countdown_note(last_snap, now, sty)
                if countdown:
                    frame += "\n" + countdown
                frame += "\n" + sty.color("  q quit", 2)

            if once:
                for line in frame.splitlines():
                    print(agent.term.truncate_ansi(line, width),
                          file=outstream)
                return _EXIT_OK

            bell = sym.bell if rang_bell else ""
            frame = "\n".join(agent.term.truncate_ansi(l, width)
                              for l in frame.splitlines())
            outstream.write(agent.term.ALT_ENTER + agent.term.HIDE_CURSOR
                            + agent.term.HOME_CLEAR + bell + frame + "\n")
            outstream.flush()

            key = poller.poll(1.0)
            if key in ("q", "Q", "ctrl-c"):
                return _EXIT_OK
    finally:
        if not once:
            outstream.write(agent.term.SHOW_CURSOR + agent.term.ALT_EXIT)
            outstream.flush()
        poller.close()


_OVERDUE_NOTE_AFTER_S = 120  # ~two missed 60s grades before we call it stalled


def _overdue_suffix(mode: str, overdue_s: float) -> str:
    """What to say when the next grade is more than a couple of intervals
    late. A stalled re-grade used to render as an eternal "checking…", which
    reads as the CLI being frozen — name the likely cause instead."""
    label = "re-grade" if mode == "honor" else "check-in"
    return (f" ({label} overdue by {agent.term.fmt_mmss(overdue_s)} — "
            "timer/agent stalled?)")


def _countdown_note(snap: dict | None, now: float, sty: Style) -> str:
    if not snap:
        return ""
    next_at = snap.get("next_event_at")
    if not next_at:
        return ""
    mode = "honor" if snap.get("mode") == "honor" else "ranked"
    remaining = float(next_at) - now
    if remaining <= 0:
        # Same language as the HTML countdown's expiry state — but escalate
        # when the wait clearly isn't a normal cadence any more.
        due = "checking…" if mode == "honor" else "checking in…"
        note = f"00:00 — {due}"
        overdue = -remaining
        tone = "muted"
        if overdue > _OVERDUE_NOTE_AFTER_S:
            note += _overdue_suffix(mode, overdue)
            tone = "warn"
        return "  " + sty.color(note, tone)
    label = "next re-grade" if mode == "honor" else "next check-in"
    return "  " + sty.color(f"{label} in {agent.term.fmt_mmss(remaining)}", "muted")


def cmd_grade(argv: list, outstream) -> int:
    positional, opts = _split_flags(
        argv, {"--quiet"}, {"--config", "--color"})
    if positional:
        raise UsageError(f"grade takes no arguments (got {positional[0]!r})")

    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0:
        raise CliError("grade runs the scoring pipeline and needs root:\n"
                       "  sudo huitz grade")

    # Deferred imports keep `huitz score` free of the collector/evaluator
    # stack and avoid an import cycle (agent/__main__ dispatches into here).
    import agent.config
    import agent.platform.detect
    import agent.__main__ as agent_main

    config_path = opts.get("--config") or _install_config_path()
    try:
        config = agent.config.load_config(config_path)
    except (OSError, ValueError) as e:
        raise CliError(f"cannot load agent config {config_path!r}: {e}") from e
    if config.mode.value == "ranked":
        raise CliError(
            "this box is ranked mode — grading happens on the engine, not "
            "here.\nThe box re-checks itself in automatically; use `huitz "
            "watch` to follow along.")

    try:
        manifest = agent_main._load_manifest(
            config.manifest_path, config.authoring_public_key_path,
            allow_unsigned=config.allow_unsigned_manifest)
    except (OSError, ValueError) as e:
        raise CliError(f"cannot load manifest: {e}") from e
    ctx = agent.platform.detect.detect()
    agent_main._prepare_forensics(
        manifest, os.path.dirname(os.path.abspath(config_path)))

    score, delta, snap = agent_main.honor_grade(config, manifest, ctx)
    # Desktop mirroring is honor_grade's last step (ordered after the write —
    # the unit's ExecStartPost races a Type=simple agent and lands one grade
    # stale), so the reading verbs see this grade immediately.

    if opts.get("--quiet"):
        change = f"  (delta {delta:+d})" if delta else ""
        print(f"graded: {score.total} pts{change}", file=outstream)
        return _EXIT_OK

    sty = _make_style(opts, outstream, snap)
    sym = Symbols(sty.utf8)
    width = agent.term.detect_width(outstream)
    if delta:
        outstream.write(sym.bell)  # the console chime already played; mirror it here
    frame = render_scorecard(snap, sty, sym, width, hints=True)
    for line in frame.splitlines():
        print(agent.term.truncate_ansi(line, width), file=outstream)
    return _EXIT_OK


def cmd_forensics(argv: list, outstream, instream) -> int:
    positional, opts = _split_flags(
        argv, set(), {"--answers", "--color", "--report"})
    sty = _make_style(opts, outstream)
    sym = Symbols(sty.utf8)
    width = agent.term.detect_width(outstream)

    if not positional:
        snap = _load_snapshot(opts.get("--report"))
        print(render_forensics(snap, sty, sym, width, opts.get("--answers")),
              file=outstream)
        return _EXIT_OK

    head = positional[0]
    if not head.isdigit():
        raise UsageError(
            f"forensics: expected a question number, got {head!r}\n"
            '  list questions:  huitz forensics\n'
            '  answer one:      huitz forensics 2 "my answer"')
    ordinal = int(head)
    text = " ".join(positional[1:]) if len(positional) > 1 else None
    snap = _load_snapshot(opts.get("--report"))
    return set_forensics_answer(snap, ordinal, text, opts.get("--answers"),
                                instream, outstream)


# --- entry -------------------------------------------------------------------------

def cmd_help(outstream) -> int:
    print(USAGE, file=outstream)
    return _EXIT_OK


def main(argv: list | None = None, outstream=None, instream=None) -> int:
    agent.term.enable_windows_vt()
    outstream = outstream or sys.stdout
    instream = instream or sys.stdin
    argv = list(sys.argv[1:] if argv is None else argv)

    if argv and argv[0] in ("-h", "--help"):
        return cmd_help(outstream)
    if not argv or argv[0] in ("help",):
        return cmd_help(outstream)

    verb, rest = argv[0], argv[1:]
    try:
        if verb == "score":
            return cmd_score(rest, outstream)
        if verb == "watch":
            return cmd_watch(rest, outstream, instream)
        if verb == "readme":
            return cmd_readme(rest, outstream)
        if verb == "grade":
            return cmd_grade(rest, outstream)
        if verb == "forensics":
            return cmd_forensics(rest, outstream, instream)
        raise UsageError(f"unknown command {verb!r}\n\n{USAGE}")
    except UsageError as e:
        print(f"huitz: {e}", file=sys.stderr)
        return _EXIT_USAGE
    except CliError as e:
        print(f"huitz: {e}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        return 130
