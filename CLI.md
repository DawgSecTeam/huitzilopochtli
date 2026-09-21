# huitz — the terminal scoring console

`huitz` is the native command-line experience for a scored Huitzilopochtli
box: the terminal twin of the Desktop `report.html`. Same grade, same
moment, same design language — one theme accent, flat "paper" layout,
semantic green/red — rendered idiomatically for a terminal instead of
ported from the web page.

```console
$ huitz
Opochtli Landing
scenario v3 · honor mode · Harbor Port Authority
──────────────────────────────────────────────────────────────────────────────

  210 pts
  [██████████████░░░░░░░░░░░░░░]  66%  ·  14 of 19 fixed  ·  5 issue(s) remain

  ✓ VULNERABILITIES FIXED — 14 of 19
    SSH root login disabled ··············································· +10
    Guest account removed ·················································· +5

  ! PENALTIES — 1
    Required firewall re-enabled ·········································· -10

  FORENSICS — 2 of 3
    ✓ Q1 Which account did the attacker create? ··························· +20
    · Q2 What was the attacker's IP address? ································ 0
      answers: /home/player/Desktop/Forensics-Questions.txt

  last graded 14:02:11 UTC  ·  next re-grade ~00:42
  try: huitz watch · huitz forensics · huitz grade
```

## Commands

| Command | What it does |
|---|---|
| `huitz score` | One-shot scorecard. Pages through `less` when the board is taller than the terminal (flat otherwise). `--json` emits the raw snapshot instead. |
| `huitz watch` | Live frame: countdown ticks each second, the board redraws the moment a new grade lands, and score changes ring the terminal bell with a session change-log. `q` quits. If a re-grade is more than a couple of minutes late, the frame says so ("re-grade overdue … timer stalled?") instead of sitting on an eternal "checking…". |
| `huitz readme` | The scenario handbook in the terminal (the theme's `readme`, embedded in the signed manifest by the compiler, carried by the snapshot). Prose re-wraps to the terminal width with inline emphasis, `code`, and links rendered; on a terminal it opens in a pager. `--raw` dumps the markdown flat. |
| `huitz forensics` | List the scenario's forensics questions with your recorded answers and last-grade verdicts. |
| `huitz forensics N` | Answer question N interactively (Enter keeps, `-` clears). |
| `huitz forensics N "text"` | Answer question N directly (scriptable). |
| `huitz grade` | Re-grade right now — the re-grade timer's work done on demand — then show the fresh scorecard. Honor boxes, root (`sudo huitz grade`). |
| `huitz help` | This list. |

Flags shared by the reading commands: `--report PATH` pins a snapshot
(accepts a `report.json`, a `report.html`, or a directory), `--color
auto|always|never` overrides color detection, and `NO_COLOR` is always
honored. `score`/`readme` take `--no-pager` to print flat even on a
terminal. Paging engages only on an interactive stream — piped output is
byte-identical to a plain print, so scripts and portals are unaffected —
and honors `$PAGER` (falling back to `less -R`, then `more`).
`grade` takes `--config PATH` for a non-default
`agent_config.json` and `--quiet` for a one-line summary.

## How it works

Nothing in `huitz score`/`watch`/`forensics` re-scores the box. Every grade
honor mode runs writes two files side by side:

```
agent grade ──► report.html   (Desktop-mirrored; the browser view)
            └─► report.json   (agent/snapshot.py — the machine-readable board)
                    │ sync-report.sh mirrors both to each user's Desktop
                    ▼
        huitz reads the snapshot and renders it in the terminal
```

The snapshot is a *presentation* of the `ScoreBreakdown` — nothing reads it
back into the evaluator, so scoring stays a pure function of
`(evidence, rubric, clock)` (architecture.md §2.1, §13). One derivation
(`agent/board.py`) feeds all three renderers: HTML, JSON snapshot, terminal.

That design is also what makes the CLI work for **any account on the box**:
the sealed install dir (`/opt/.huitzilopochtli/`, 0700 root) is never
touched by the reading commands — they read the Desktop copy, exactly like
the browser shortcut does.

### Honor vs ranked presentation

- **Honor** renders the CyberPatriot-style board: only fixed vulnerabilities
  and incurred penalties are named; failed checks stay anonymous (a count
  only). The snapshot preserves that contract — there is no `results` list
  in an honor `report.json`, so `cat`/`jq` on the Desktop copy spoils
  exactly as little as the HTML does.
- **Ranked** renders the engine's diagnostic view: per-check results with
  reasons, SLA states, and "the engine's authoritative score" labeling —
  mirroring the ranked HTML table (safe on-box: the rubric never shipped to
  the box). Before the first engine response, `score` and `watch` show
  *submitted — awaiting engine*. `huitz grade` explains that ranked grading
  happens engine-side and suggests `watch`.

### Score-change behavior

The grade itself (timer or `huitz grade`) plays the box's gain-chime /
penalty-alarm and raises the desktop toast exactly as before
(`agent/notify.py`) — alerts belong to the grade, not to whichever terminal
happens to be open. The CLI adds the terminal-native layer on top: `watch`
rings the terminal bell (audible over SSH, where PulseAudio isn't) and logs
the change in its "this session" section; `grade` rings the bell once when
the grade it just ran changed the score.

## Forensics from the terminal

`huitz forensics` shows each question, your current answer as the answers
file records it, and the last grade's verdict. Answering writes the same
`Forensics-Questions.txt` the collector reads — the terminal is just a
better editor for one line:

```console
$ huitz forensics 2 "203.0.113.7"
✓ Q2 answered: "203.0.113.7"
It scores on the next re-grade (about a minute), or: sudo huitz grade
```

The file is edited surgically: only the targeted `Answer:` line changes,
ownership and permissions are preserved, and a missing template is recreated
from the snapshot (write-if-missing, never clobbering existing answers).
Answers re-grade automatically on the next timer tick — no restart, same as
editing the file by hand.

## Installation

**boxbuilder installs the CLI automatically** on POSIX boxes: the install
step copies the agent zipapp to `/usr/local/bin/huitz` (`install -m 755`).
A copy, not a symlink — the install dir is sealed 0700 and a symlink would
be unusable to non-root accounts. If that step warns (e.g. no
`/usr/local/bin`), the box still grades and reports normally; add the shim
by hand:

```bash
sudo install -m 755 /opt/.huitzilopochtli/agent.pyz /usr/local/bin/huitz
```

The same install step plants a first-login banner
(`/etc/update-motd.d/90-huitzilopochtli`) that introduces these commands —
that's how most players meet `huitz`.

(Existing boxes built before this feature: run that one line, and make sure
the installed `sync-report.sh` is the current one so `report.json` gets
mirrored — or just run it once by hand after the next grade.)

**Windows** boxes have no shim; run the zipapp directly from PowerShell:

```powershell
py C:\ProgramData\huitzilopochtli\agent.pyz score
```

The CLI enables VT processing on Windows consoles automatically and reads
the Public Desktop `report.json` that the scheduled-task wrapper mirrors.

## Discovery order

`huitz` locates a snapshot to read by trying, in order:

1. `--report PATH` (or `$HUITZ_REPORT`) when given — authoritative, no
   fallback;
2. this box's install dir via `agent_config.json` (or `$HUITZ_CONFIG`);
   root reaches the sealed dir directly here;
3. your own Desktop's `report.json`;
4. any other real user's Desktop copy (the same uid-1000-59999 +
   login-shell heuristic `sync-report.sh` uses).

The first readable snapshot wins, so an SSH session as root shows the same
grade the desktop user's browser shows. A missing snapshot produces a
message telling you how to produce one; a corrupt or newer-version
snapshot is reported verbatim instead of misrendered.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | success |
| `1` | runtime failure (no snapshot, unreadable manifest, …) |
| `2` | usage error (unknown command/flag, missing value) |
| `130` | interrupted (`Ctrl-C`) |

## For maintainers

- `agent/cli.py` — commands + rendering; reads snapshots, never scores
  (except `grade`, which delegates to `agent/__main__.honor_grade`).
- `agent/term.py` — the terminal kit: color-depth detection (NO_COLOR /
  16 / 256 / truecolor), unicode-vs-ASCII symbols, width handling, the
  alternate-screen key poller (termios/select on POSIX, `msvcrt` on
  Windows). No curses: the zipapp must stay curses-free for Windows.
- `agent/board.py` — the one derivation behind HTML, snapshot, and
  terminal; change scoring-adjacent display facts there, not in a
  renderer.
- `agent/snapshot.py` — the `report.json` format (`snapshot_version` 1).
  The CLI refuses snapshots from newer majors with an upgrade hint rather
  than misrendering.
- `agent/answers.py` — the forensics answers-file format, shared by the
  collector, the template writer, and the CLI's answer editor.
