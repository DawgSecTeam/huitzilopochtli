"""Forensics answers-file primitives — one implementation of the format.

Format, one block per question (all three consumers — collector, template
writer, CLI — share it):

    Q<ordinal>: <question text>
    Answer: <team's answer>

An untouched template carries the underscore blank; scoring itself lives in
common/matchers.py (`answer_equals`), not here."""
import re
import subprocess
import sys

ANSWER_PLACEHOLDER_RE = re.compile(r"^_+$")
QUESTION_RE = re.compile(r"^Q(\d+):")
ANSWER_RE = re.compile(r"^Answer:(.*)$", re.IGNORECASE)

# Read cap: the answers file is team-editable and must not be memory-leverage.
CONTENT_LIMIT = 1_000_000

_BLANK = "_" * 44

def blank_line() -> str:
    """The untouched-template Answer line (what a fresh template shows)."""
    return f"Answer: {_BLANK}"

def extract_answer(content: str, ordinal: int) -> tuple:
    """Return (answer_or_None, found): stripped Answer: text after Q<ordinal>;
    None only when empty. The underscore placeholder comes back AS-IS —
    callers decide what it means (collector reports it, matchers ignore it)."""
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
    """Return (new_content, found); every other byte of the team's file is
    preserved. Empty text restores the blank placeholder; a deleted Answer
    line is re-inserted under the Q line; found=False means no such block."""
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

def extract_questions(content: str) -> dict:
    """{ordinal: question text} for a rendered answers file."""
    out = {}
    for line in content.splitlines():
        m = QUESTION_RE.match(line.strip())
        if m:
            out[int(m.group(1))] = line.strip()[len(m.group(0)):].strip()
    return out

def is_stale_blank_template(content: str, questions: list) -> bool:
    """True when `content` is an UNTOUCHED answers file whose questions are
    not `questions` — a sealed image shipping the previous scenario's
    template. One real answer anywhere and the file belongs to the team."""
    for ordinal, _text in questions:
        answer, _found = extract_answer(content, ordinal)
        if answer and not ANSWER_PLACEHOLDER_RE.match(answer):
            return False
    want = {int(ordinal): str(text) for ordinal, text in questions}
    return extract_questions(content) != want

# The child below runs already-dropped to the file owner's uid/gid, so a
# symlink planted in their directory can only redirect the write to where
# that user could write anyway.
_WRITE_AS_OWNER = (
    "import os,sys,tempfile\n"
    "p=sys.argv[1]\n"
    "data=sys.stdin.buffer.read().decode('utf-8', 'replace')\n"
    "fd,t=tempfile.mkstemp(dir=os.path.dirname(p) or '.',prefix='.huitz-')\n"
    "try:\n"
    "    with os.fdopen(fd,'w',encoding='utf-8') as f: f.write(data)\n"
    "    os.chmod(t,int(sys.argv[2],8)); os.replace(t,p)\n"
    "except BaseException:\n"
    "    os.unlink(t); raise\n"
)

def write_as_owner(path: str, content: str, uid: int, gid: int,
                   mode: int = 0o666) -> None:
    """Atomically replace `path` with `content`, writing as uid:gid (POSIX).

    Root writing into a user-controlled dir must not follow a planted
    symlink onto root-owned files — so the write happens as that user."""
    subprocess.run(
        [sys.executable, "-c", _WRITE_AS_OWNER, path, oct(mode)],
        input=content, text=True, encoding="utf-8", user=uid, group=gid,
        extra_groups=[],
        check=True, timeout=15,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
