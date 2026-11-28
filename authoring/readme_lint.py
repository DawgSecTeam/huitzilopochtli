"""Readme spoiler lint: keeps the player-facing handbook off the answer key.

Runs at compile time (authoring/compile.py) and returns (errors, warnings):
forensics answers always error, tier-5 findings error only in ranked builds,
lesser leaks warn. Writing rules: HANDBOOK_GUIDE.md. A net, not a judge.
"""
import html as _html
import re
import string

_GENERIC_ANSWERS = {
    "true", "false", "yes", "no", "none", "unknown", "n/a", "na", "nil",
    "null", "password", "username",
}
_MIN_ANSWER_CHARS = 4

_MIN_SOLUTION_LINE_CHARS = 20
_MIN_SOLUTION_LINE_WORDS = 3

_MIN_PATH_CHARS = 6


def _visible_text(text: str) -> str:
    """Approximate the text a player actually sees in the rendered page.

    Strips tags/entities, links, and emphasis/code markers so markup splits
    (``cocoa-**hidden**-sync``) can't hide a leak. A net, not a renderer.
    """
    visible = str(text)
    visible = re.sub(r"<[^>]*>", "", visible)
    visible = _html.unescape(visible)
    visible = re.sub(r"!\[([^\]]*)\]\([^)]*\)", r"\1", visible)
    visible = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", visible)
    visible = visible.replace("`", "")
    visible = re.sub(r"(\*\*|__|\*|_)", "", visible)
    return visible


def _norm(text: str) -> str:
    """Casefold + collapse whitespace, so wrapped/rendered markdown matches."""
    return " ".join(_visible_text(text).casefold().split())


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
                continue
            if _contains(readme_norm, needle):
                errors.append(
                    f"readme leak: forensics answer {raw!r} ({question.get('id', '?')}) "
                    "appears in the handbook — answers live in the rubric and the "
                    "post-event answer key, never in theme.readme"
                )
    return errors



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



_FENCE_RE = re.compile(r"^\s*(?:```|~~~)")
_INLINE_SPAN_RE = re.compile(r"`([^`\n]+)`")

_PROMPT = r"(?:ps\s+[a-z]:\\[^\n>]*>?\s*)?(?:sudo\s+)?"

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



_WIN_PATH_RE = re.compile(r"[A-Za-z]:\\[^\s'\"`|<>*:]+(?:\\[^\s'\"`|<>*:]+)+")
_POSIX_PATH_RE = re.compile(r"/[\w.@+-]+(?:/[\w.@+-]+){2,}")

# Canonical OS locations a handbook may legitimately name.
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
        r"(?<![a-z0-9\\])" + re.escape(needle_norm) + r"(?![\w@+/-])",
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
                    continue
                if _path_present(readme_norm, needle):
                    warnings.append(
                        f"readme leak: planted path {token!r} (from the solution: of "
                        f"{check_id}) appears in the handbook — planted artifact "
                        "locations are the player's job to find"
                    )
    return warnings


_DIFFICULTY_PREFIX_RE = re.compile(
    r"^(?:easy|moderate|hard|trivial|advanced|critical|penalty)\s+", re.I
)

_UNIT_NAME_RE = re.compile(r"\b[a-z0-9_.@-]+\.(?:service|timer|socket|path|mount|target)\b", re.I)

_GENERIC_NAMES = {
    "root", "admin", "administrator", "sudo", "shadow", "www-data", "nobody",
    "daemon", "service", "cron", "atd", "ssh", "sshd", "ssh.service",
}

_END_STATE_NGRAM = 6

_PROSE_MUTATION_RE = re.compile(
    r"(?:disable|enable|mask|stop|kill|remove|delete|uninstall|purge|turn\s+off|turn\s+on)\b"
    r"[^\n]*?(?:\w+'s|\bits\b)[^\n]*?"
    r"\b(?:launcher|drop-?in|timer|unit|service|daemon|beacon|payload|malware|"
    r"persistence|hook|cron\s+job|startup\s+script|sudoers|binary|registry)\b",
    re.I,
)

# "How many ..." forensics questions whose numeric answer must not appear.
_COUNT_QUESTION_RE = re.compile(r"\b(?:how many|number of|count of|total of)\b", re.I)

_PROSE_MUTATION_EXCLUSION_RE = re.compile(r"scoring engine|\bhuitz\b|the agent\b", re.I)


def _walk_strings(node):
    if isinstance(node, dict):
        for value in node.values():
            yield from _walk_strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk_strings(value)
    elif isinstance(node, str):
        yield node


def _allowed_names(parsed: dict) -> set:
    """Names the handbook must carry: the must-stay-up services (penalty
    checks' collected names plus the scored `services:` block) — required
    briefing."""
    allowed = set()
    for check in parsed.get("checks") or []:
        if check.get("category") == "penalty":
            for value in _walk_strings(check.get("collect") or {}):
                allowed.add(_norm(value))
    for service in parsed.get("services") or []:
        for value in _walk_strings(service):
            allowed.add(_norm(value))
    return allowed


def _planted_identifiers(parsed: dict, readme_norm: str) -> list:
    """Planted unit/account names that appear in the handbook."""
    findings = []
    allowed = _allowed_names(parsed)
    seen = set()

    def flag(name: str, source: str):
        needle = _norm(name).strip(".")
        if len(needle) < 3 or needle in seen or needle in _GENERIC_NAMES:
            return
        if any(needle in a or a in needle for a in allowed if len(a) >= 3):
            return
        seen.add(needle)
        if _contains(readme_norm, needle):
            findings.append(
                f"readme leak: planted name {name!r} ({source}) appears in the "
                "handbook — planted units/accounts are the player's job to find"
            )

    for check in parsed.get("checks") or []:
        cid = check.get("id", "?")
        if check.get("category") not in ("vuln", "prohibited"):
            continue
        collect = check.get("collect") or {}
        for key in ("service", "unit", "timer", "username", "account", "user"):
            value = collect.get(key)
            if isinstance(value, str):
                flag(value, f"collect.{key} of {cid}")
        expect = check.get("expect") or {}
        if expect.get("user_absent"):
            flag(str(expect.get("username", "")), f"expect.username of {cid}")
        solution = check.get("solution")
        items = solution if isinstance(solution, list) else ([solution] if solution else [])
        for item in items:
            for token in _UNIT_NAME_RE.findall(str(item)):
                flag(token, f"solution: of {cid}")
                stem = re.split(r"[.(]", token)[0]
                if len(stem) >= 5:
                    flag(stem, f"solution: of {cid}")
    return findings


def _end_state_paraphrases(parsed: dict, readme_norm: str) -> list:
    """Long n-grams of a scored end-state (check display title) in the handbook."""
    findings = []
    seen = set()
    for check in parsed.get("checks") or []:
        display = check.get("display")
        if not isinstance(display, str):
            continue
        words = _norm(_DIFFICULTY_PREFIX_RE.sub("", display)).split()
        if len(words) < _END_STATE_NGRAM:
            continue
        grams = {" ".join(words[i:i + _END_STATE_NGRAM])
                 for i in range(len(words) - _END_STATE_NGRAM + 1)}
        for gram in grams:
            if gram in seen:
                continue
            if _contains(readme_norm, gram):
                seen.add(gram)
                findings.append(
                    f"readme leak: handbook text paraphrases the scored end-state of "
                    f"{check.get('id', '?')}: {gram!r} — end-states live in the rubric"
                )
                break
    return findings


def _count_reveals(parsed: dict, readme_text: str) -> list:
    """Numeric answers to 'how many' forensics questions appearing in the handbook."""
    findings = []
    for question in parsed.get("forensics") or []:
        qtext = _norm(question.get("question", ""))
        if not _COUNT_QUESTION_RE.search(qtext):
            continue
        answers = []
        if question.get("answer") is not None:
            answers.append(str(question["answer"]))
        answers.extend(str(a) for a in (question.get("answers") or []))
        for raw in answers:
            needle = _strip_punct(_norm(raw))
            if not needle.isdigit():
                continue
            for line in readme_text.splitlines():
                body = re.sub(r"^\s*(?:[-*•]|\d+[.)])\s*", "", line)
                if re.search(r"(?<!\d)" + re.escape(needle) + r"(?!\d)", body):
                    findings.append(
                        f"readme leak: the count answer {raw!r} "
                        f"({question.get('id', '?')}) appears in the handbook — "
                        "finding counts are the player's to discover"
                    )
                    break
    return findings


def _prose_mutations(readme_text: str) -> list:
    """Fix instructions in prose (not code spans): 'disable its launcher'."""
    findings = []
    in_fence = False
    for line in readme_text.splitlines():
        if _FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if in_fence or _INLINE_SPAN_RE.search(line):
            continue
        if _PROSE_MUTATION_EXCLUSION_RE.search(line):
            continue
        if _PROSE_MUTATION_RE.search(line):
            findings.append(
                f"readme leak: prose fix instruction in the handbook: {line.strip()[:80]!r} "
                "— the handbook teaches inspection, not fixes"
            )
    return findings



def lint_readme(parsed: dict, readme_text: str, mode: str = "honor") -> tuple:
    """Lint handbook text against the effective (merged) scenario dict.

    Returns (errors, warnings); errors block the compile. ``mode`` is the
    build target: tier-5 findings error in ranked, warn in honor."""
    readme_norm = _norm(readme_text)
    errors = _forensics_answer_leaks(parsed, readme_norm)
    tier5 = (
        _planted_identifiers(parsed, readme_norm)
        + _end_state_paraphrases(parsed, readme_norm)
        + _count_reveals(parsed, readme_text)
        + _prose_mutations(readme_text)
    )
    warnings = (
        _solution_copy_paste(parsed, readme_norm)
        + _mutation_commands(readme_text)
        + _planted_paths(parsed, readme_norm)
    )
    if mode == "ranked":
        errors = errors + tier5
    else:
        warnings = warnings + tier5
    return errors, warnings
