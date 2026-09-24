"""Readme spoiler lint: keeps the player-facing handbook off the answer key.

The handbook (`theme.readme`) is the assignment, not the answer key — see
HANDBOOK_GUIDE.md for the writing rules. This module is the mechanical net
under those rules. It runs at compile time
(authoring/compile.py::compile_scenario) and reports two severities:

- **errors** — a forensics answer verbatim in the readme. That is never
  legitimate, so it blocks the compile like any other validation error.
- **warnings** — walkthrough copy-paste, mutation commands, and planted
  paths in the readme. Warnings are surfaced by boxbuilder (like the answer
  key's missing-walkthroughs note) and asserted clean by the all-boxes
  regression test, so new leaks need an explicit decision to ship.

It is a net, not a judge: a prose spec-sheet of scored end-states with no
commands and no planted names passes cleanly. The one-question test in
HANDBOOK_GUIDE.md ("could a player earn this check by copying the
handbook?") is the human half of the review.
"""
import re
import string

# Tier 1 (error): forensics answers. Short or generic values are skipped, as
# are answers the question text itself already prints (freebies by design)
# and answers listed in theme.readme_lint_allow (lenient aliases that collide
# with the box's story vocabulary — see HANDBOOK_GUIDE.md).
_GENERIC_ANSWERS = {
    "true", "false", "yes", "no", "none", "unknown", "n/a", "na", "nil",
    "null", "password", "username",
}
_MIN_ANSWER_CHARS = 4

# Tier 2 (warning): whole-line overlap with authored `solution:` walkthroughs.
_MIN_SOLUTION_LINE_CHARS = 20
_MIN_SOLUTION_LINE_WORDS = 3

# Tier 4 (warning): absolute paths planted in `solution:` text that also show
# up in the readme. Paths that a check openly collects (crown-jewel briefing:
# the permission checks collect exactly the confidential paths the readme
# names) are exact-matched against collect params and skipped.
_MIN_PATH_CHARS = 6


def _norm(text: str) -> str:
    """Casefold + collapse whitespace, so wrapped markdown still matches."""
    return " ".join(str(text).casefold().split())


def _strip_punct(text: str) -> str:
    return text.strip(string.punctuation + " \t")


def _contains(haystack_norm: str, needle_norm: str) -> bool:
    """Word-bounded containment on normalized text ('intern' != 'internal')."""
    if not needle_norm:
        return False
    return re.search(
        r"(?<![a-z0-9])" + re.escape(needle_norm) + r"(?![a-z0-9])",
        haystack_norm,
    ) is not None


# --- tier 1: forensics answers (error) --------------------------------------

def _readme_lint_allow(parsed: dict) -> set:
    theme = parsed.get("theme") or {}
    allow = theme.get("readme_lint_allow") or []
    return {_strip_punct(_norm(a)) for a in allow if str(a).strip()}


def _forensics_answer_leaks(parsed: dict, readme_norm: str) -> list:
    errors = []
    allowed = _readme_lint_allow(parsed)
    for question in parsed.get("forensics") or []:
        answers = []
        if question.get("answer") is not None:
            answers.append(str(question["answer"]))
        answers.extend(str(a) for a in (question.get("answers") or []))
        question_norm = _norm(question.get("question", ""))
        for raw in answers:
            needle = _strip_punct(_norm(raw))
            if len(needle) < _MIN_ANSWER_CHARS or needle in _GENERIC_ANSWERS:
                continue
            if needle in allowed:
                continue
            if _contains(question_norm, needle):
                continue  # the question text already gives it away by design
            if _contains(readme_norm, needle):
                errors.append(
                    f"readme leak: forensics answer {raw!r} ({question.get('id', '?')}) "
                    "appears in the handbook — answers live in the rubric and the "
                    "post-event answer key, never in theme.readme"
                )
    return errors


# --- tier 2: solution: copy-paste (warning) ---------------------------------

def _iter_solutions(parsed: dict, *, include_forensics: bool = True):
    for check in parsed.get("checks") or []:
        yield check.get("id", "?"), check.get("solution")
    if include_forensics:
        for question in parsed.get("forensics") or []:
            yield question.get("id", "?"), question.get("solution")


def _solution_copy_paste(parsed: dict, readme_norm: str) -> list:
    warnings = []
    for check_id, solution in _iter_solutions(parsed):
        items = solution if isinstance(solution, list) else ([solution] if solution else [])
        for item in items:
            for line in str(item).splitlines():
                needle = _strip_punct(_norm(line))
                if (len(needle) < _MIN_SOLUTION_LINE_CHARS
                        or len(needle.split()) < _MIN_SOLUTION_LINE_WORDS):
                    continue
                if _contains(readme_norm, needle):
                    warnings.append(
                        f"readme leak: a line from the solution: of {check_id} appears "
                        f"verbatim in the handbook: {line.strip()[:70]!r} — walkthrough "
                        "material belongs in solution: / the answer key"
                    )
                    break
    return warnings


# --- tier 3: mutation commands in code spans and fences (warning) -----------

_FENCE_RE = re.compile(r"^\s*(?:```|~~~)")
_INLINE_SPAN_RE = re.compile(r"`([^`\n]+)`")

# Optional PowerShell prompt / sudo ahead of an anchored command.
_PROMPT = r"(?:ps\s+[a-z]:\\[^\n>]*>?\s*)?(?:sudo\s+)?"

# PowerShell mutating cmdlets (anywhere in the fragment; Get-* stays legal).
_PS_MUTATING_RE = re.compile(
    r"\b(Set|Stop|Suspend|Remove|Disable|Enable|Clear|Uninstall|Revoke|Block|"
    r"Rename|Reset|New|Add|Import|Invoke|Restart)-[A-Z]\w+"
)

_ANCHORED_MUTATIONS = [
    (re.compile("^" + _PROMPT + r"(?:chmod|chown|chgrp|chattr|setfacl|passwd|smbpasswd"
                r"|useradd|userdel|usermod|groupadd|groupdel|visudo)\b"),
     "changes accounts or permissions"),
    (re.compile("^" + _PROMPT + r"systemctl\s+(?:stop|start|restart|disable|enable|mask|kill)\b"),
     "changes a service state"),
    (re.compile("^" + _PROMPT + r"service\s+\S+\s+(?:stop|start|restart|disable|enable)\b"),
     "changes a service state"),
    (re.compile("^" + _PROMPT + r"(?:apt|apt-get|dnf|yum|zypper)\s+(?:remove|purge|erase|autoremove)\b"),
     "removes packages"),
    (re.compile("^" + _PROMPT + r"(?:rm|del|erase|rd|rmdir)\b"),
     "deletes files"),
    (re.compile("^" + _PROMPT + r"ufw\s+(?:allow|deny|reject|limit|delete|default|disable|enable)\b"),
     "changes a firewall"),
    (re.compile("^" + _PROMPT + r"ip6?tables(?:-legacy)?(?:\s+-t\s+\w+)?\s+(?:-[ADIERDFNZX])\b"),
     "changes iptables rules or policies"),
    (re.compile("^" + _PROMPT + r"reg\s+(?:add|delete|load|unload|restore|save|import)\b", re.I),
     "writes the registry"),
    (re.compile("^" + _PROMPT + r"sc(?:\.exe)?\s+(?:config|create|delete|stop|start|failure)\b", re.I),
     "changes a Windows service"),
    (re.compile("^" + _PROMPT + r"net\s+(?:user|localgroup|group|accounts)\b[^/\n]*?/(?![\w.]*\bdomain\b)\w",
                re.I),
     "changes account policy or membership"),
    (re.compile(r"\bauditpol\s+/set\b", re.I),
     "changes audit policy"),
    (re.compile(r"\bnetsh\s+(?:advfirewall|firewall|set|reset)\b", re.I),
     "changes Windows networking/firewall"),
    (re.compile(r"\bicacls\s+\S+\s+/(?:grant|deny|remove|reset|inherit|setintegritylevel)\b", re.I),
     "changes file ACLs"),
    (re.compile(r"\bschtasks\s+/(?:create|delete|change|run|end)\b", re.I),
     "changes scheduled tasks"),
]

_MUTATION_EXCLUSION_RE = re.compile(
    r"^(?:-|huitz\s)"  # bare flags like `-P`, huitz CLI verbs
)


def _mutation_commands(readme_text: str) -> list:
    warnings = []
    seen = set()
    in_fence = False

    def check(fragment: str, where: str):
        fragment = fragment.strip()
        if not fragment or _MUTATION_EXCLUSION_RE.match(fragment):
            return
        hit = _PS_MUTATING_RE.search(fragment)
        label = hit.group(0) if hit else None
        if not label:
            for pattern, what in _ANCHORED_MUTATIONS:
                m = pattern.search(fragment)
                if m:
                    label = f"{m.group(0).strip()} — {what}"
                    break
        if label:
            key = (label, fragment[:60])
            if key not in seen:
                seen.add(key)
                warnings.append(
                    f"readme leak: mutation command in a code {where}: {fragment[:70]!r} "
                    f"({label}) — the handbook teaches inspection, not fixes"
                )

    for line in readme_text.splitlines():
        if _FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            check(line, "block")
        else:
            for match in _INLINE_SPAN_RE.finditer(line):
                check(match.group(1), "span")
    return warnings


# --- tier 4: planted paths from solutions (warning) --------------------------

# Depth floors: >= 3 POSIX segments (kills /etc/passwd-style coaching files)
# and >= 2 segments after the drive (kills generic parents like C:\ProgramData
# while keeping C:\ProgramData\Subsystems-class planted directories).
_WIN_PATH_RE = re.compile(r"[A-Za-z]:\\[^\s'\"`|<>*:]+(?:\\[^\s'\"`|<>*:]+)+")
_POSIX_PATH_RE = re.compile(r"/[\w.@+-]+(?:/[\w.@+-]+){2,}")

# Canonical OS locations a pinecrest-ceiling handbook may legitimately name —
# where standard features live (the SYSVOL path is the Run-key-path class),
# as opposed to attacker-planted names.
_GENERIC_PATHS = {
    "c:\\windows\\sysvol",
    "c:\\windows\\sysvol\\domain\\policies",
    "c:\\windows\\system32\\drivers\\etc\\hosts",
    "/etc/hosts",
}


def _collect_strings(parsed: dict) -> set:
    """Every string value inside checks' collect params (openly-scored paths)."""
    values = set()

    def walk(node):
        if isinstance(node, dict):
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
        elif isinstance(node, str):
            values.add(_norm(node))

    for check in parsed.get("checks") or []:
        walk(check.get("collect") or {})
    return values


def _path_present(haystack_norm: str, needle_norm: str) -> bool:
    """Containment that will not match a parent dir of a longer named path
    ('/home/x/.ssh' must not fire on the briefed '/home/x/.ssh/id_rsa')."""
    return re.search(
        r"(?<![a-z0-9\\])" + re.escape(needle_norm) + r"(?![\w.@+/-])",
        haystack_norm,
    ) is not None


def _planted_paths(parsed: dict, readme_norm: str) -> list:
    warnings = []
    collected = _collect_strings(parsed)
    seen = set()
    for check_id, solution in _iter_solutions(parsed, include_forensics=False):
        items = solution if isinstance(solution, list) else ([solution] if solution else [])
        for item in items:
            for token in _WIN_PATH_RE.findall(str(item)) + _POSIX_PATH_RE.findall(str(item)):
                needle = _norm(token).strip(".")
                if len(needle) < _MIN_PATH_CHARS or needle in seen:
                    continue
                seen.add(needle)
                if needle in _GENERIC_PATHS or needle in collected:
                    continue  # OS-canonical or openly collected => fair game
                if _path_present(readme_norm, needle):
                    warnings.append(
                        f"readme leak: planted path {token!r} (from the solution: of "
                        f"{check_id}) appears in the handbook — planted artifact "
                        "locations are the player's job to find"
                    )
    return warnings


# --- entry point --------------------------------------------------------------

def lint_readme(parsed: dict, readme_text: str) -> tuple:
    """Lint the handbook (theme.readme text) against a parsed scenario.

    Returns (errors, warnings): errors block the compile; warnings are
    surfaced by boxbuilder and must stay empty for the boxes in-repo (the
    all-boxes regression test enforces that).
    """
    readme_norm = _norm(readme_text)
    errors = _forensics_answer_leaks(parsed, readme_norm)
    warnings = (
        _solution_copy_paste(parsed, readme_norm)
        + _mutation_commands(readme_text)
        + _planted_paths(parsed, readme_norm)
    )
    return errors, warnings
