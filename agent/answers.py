"""Forensics answers-file primitives — one implementation of the file format.

The answers file is team-editable and lives on the primary desktop user's
Desktop by default (agent/__main__._prepare_forensics resolves the path).
Three consumers share the format so they cannot drift:

  agent/checks/forensics.py  — collector: extracts one question's answer
                               as evidence
  agent/__main__.py          — writes the initial template (write-if-missing)
  agent/cli.py               — `huitz forensics`: displays and edits answers
                               in place from the terminal

Format — one block per question:

    Q<ordinal>: <question text>
    Answer: <team's answer>

An untouched template carries a long underscore blank on the Answer line; a
blank or missing Answer line reads as unanswered (empty string). Scoring of
the extracted string lives in common/matchers.py (`answer_equals`), not here.
"""
import re
import subprocess
import sys

ANSWER_PLACEHOLDER_RE = re.compile(r"^_+$")
QUESTION_RE = re.compile(r"^Q(\d+):")
ANSWER_RE = re.compile(r"^Answer:(.*)$", re.IGNORECASE)

# Cap read size — the answers file is team-editable and must not be a
# memory-exhaustion lever (mirrors agent/checks/forensics.py's limit).
CONTENT_LIMIT = 1_000_000  # 1 MB

_BLANK = "_" * 44


def blank_line() -> str:
    """The untouched-template Answer line (what a fresh template shows)."""
    return f"Answer: {_BLANK}"


def extract_answer(content: str, ordinal: int) -> tuple:
    """Return (answer_or_None, found).

    Answer is the text on the Answer: line following the Q<ordinal> line,
    stripped; None only when the line is truly empty. An untouched
    underscore placeholder comes back AS the placeholder text — callers
    decide what to do with it (the collector reports "still has the blank
    placeholder"; `answer_equals` in common/matchers.py treats it as
    unanswered; the CLI displays it as blank).
    """
    lines = content.splitlines()
    current_ordinal = None
    found = False
    answer = None
    for line in lines:
        qmatch = QUESTION_RE.match(line.strip())
        if qmatch:
            current_ordinal = int(qmatch.group(1))
            if current_ordinal == ordinal:
                found = True
            continue
        if current_ordinal != ordinal:
            continue
        amatch = ANSWER_RE.match(line.strip())
        if amatch:
            answer = amatch.group(1).strip() or None
            break
    return answer, found


def set_answer(content: str, ordinal: int, text: str) -> tuple:
    """Return (new_content, found) with question `ordinal`'s answer set.

    Only the targeted Answer line is touched; every other byte of the
    team's file is preserved. Empty `text` restores the untouched blank
    placeholder rather than leaving a bare "Answer:" line. If the block
    exists but its Answer line was deleted by the team, a new Answer line
    is inserted directly under the Q<ordinal> line. Returns found=False
    when no Q<ordinal> block exists (caller decides whether to append one).
    """
    lines = content.splitlines()
    replacement = blank_line() if (text is None or text == "") else f"Answer: {text}"
    out = []
    current_ordinal = None
    found = False
    inserted = False
    for line in lines:
        qmatch = QUESTION_RE.match(line.strip())
        if qmatch:
            current_ordinal = int(qmatch.group(1))
            if current_ordinal == ordinal:
                found = True
        elif current_ordinal == ordinal and not inserted and ANSWER_RE.match(line.strip()):
            out.append(replacement)
            inserted = True
            continue
        out.append(line)
    if found and not inserted:
        # Q block exists but lost its Answer line: re-insert under the
        # Q line (immediately after it, preserving everything else).
        for i, line in enumerate(out):
            qmatch = QUESTION_RE.match(line.strip())
            if qmatch and int(qmatch.group(1)) == ordinal:
                out.insert(i + 1, replacement)
                break
    body = "\n".join(out)
    if out and content.endswith("\n"):
        body += "\n"
    return body, found


def render_template(questions: list) -> str:
    """Render the answers template for `questions` as [(ordinal, text)]."""
    lines = [
        "Forensics Questions",
        "===================",
        "",
        "Answer each question below by replacing the blank on its 'Answer:'",
        "line. Answers are collected and scored automatically each time the",
        "box re-grades: a correct answer earns the question's points, a wrong",
        "or blank answer earns nothing and never deducts.",
        "",
    ]
    for ordinal, question in questions:
        lines.append(f"Q{ordinal}: {question}")
        lines.append(blank_line())
        lines.append("")
    return "\n".join(lines)


# Runs in a child process that has already dropped to the file owner's uid/gid
# (subprocess user=/group=), so a symlink planted in the owner's directory
# can only redirect the write to somewhere that user could write anyway.
_WRITE_AS_OWNER = (
    "import os,sys,tempfile\n"
    "p=sys.argv[1]\n"
    "fd,t=tempfile.mkstemp(dir=os.path.dirname(p) or '.',prefix='.huitz-')\n"
    "try:\n"
    "    with os.fdopen(fd,'w',encoding='utf-8') as f: f.write(sys.stdin.read())\n"
    "    os.chmod(t,int(sys.argv[2],8)); os.replace(t,p)\n"
    "except BaseException:\n"
    "    os.unlink(t); raise\n"
)


def write_as_owner(path: str, content: str, uid: int, gid: int,
                   mode: int = 0o666) -> None:
    """Atomically replace `path` with `content`, writing as uid:gid (POSIX).

    For root writing into a directory a desktop user controls (their
    Desktop/answers file): writing as root would follow any symlink the user
    planted there onto root-owned files. Raises CalledProcessError or
    OSError on failure.
    """
    subprocess.run(
        [sys.executable, "-c", _WRITE_AS_OWNER, path, oct(mode)],
        input=content, text=True, user=uid, group=gid, extra_groups=[],
        check=True, timeout=15,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
