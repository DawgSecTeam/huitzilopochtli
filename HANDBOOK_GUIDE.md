# HANDBOOK_GUIDE.md — writing box handbooks that don't give away the answers

Every box ships a player-facing handbook: `theme.readme` in the scenario
(conventionally `boxes/<box>/assets/README.md`). It is embedded in the signed
manifest, rendered by `huitz readme` on the box, and planted as `README.html`
into each user's Documents mirror. This guide is the bar a handbook must meet;
`authoring/readme_lint.py` is the mechanical net under it, and
`tests/unit/test_authoring_readme_lint.py::test_every_box_in_repo_is_lint_clean`
keeps every in-repo box clean.

## The bar

**The handbook is the assignment, not the answer key.** A player who reads
only the handbook should know the mission, the ground rules, and where the
danger is — and still have to investigate to score.

The reference implementation is `boxes/chocolate-factory/assets/README.md`:
47 lines, zero command blocks, zero planted artifact names. From a one-line
roster and three file paths, a player must find 20 findings. That is the
whole genre: the handbook supplies *ground truth* (roster, crown jewels,
critical services); the box supplies the evidence; the score report supplies
the per-finding hints as they are earned.

## The chocolate-factory skeleton

Six sections, in this order. Each has a strict information budget:

1. **Title + one-paragraph assignment** — narrative voice, categories only:
   "Remove unauthorized access, harden SSH, and clean up files and services
   left behind by the intruder." No artifact names, no locations.
2. **## Scenario** — the mission restated as operator verbs plus the one
   anti-overblocking constraint ("the ubuntu user password does not need to
   be changed"). Constraints the *grader* applies are fair game here; the
   states the *checks* score are not.
3. **Critical services** — only what prevents bricking the box (SSH must
   keep running). This is protective briefing, not a hint.
4. **Authorized users** — the roster. It defines "unauthorized" by complement:
   three legitimate names are enough to make the player find four rogues
   without any of them being named.
5. **Confidential files** — the crown-jewel paths. Stating *what is
   confidential* is required briefing (it defines the permissions objective);
   what to do to those files is withheld.
6. **Mechanics** — forensics how-to (graded from the file, one short
   specific answer each), how to read the score report, and the
   do-not-delete-the-scoring-engine warning.

## The information budget

**Belongs in the handbook:**

- the mission and its narrative frame;
- the roster (authorized users/service accounts — the complement is the
  hunt);
- crown-jewel paths (they *are* the scored objective's subject);
- critical services and protective constraints ("do not lock yourself out",
  static-pine's "cron/atd are load-bearing — killing them costs points");
- mechanics: grading cadence, where to type forensics answers, format
  constraints ("this host scores raw iptables; ufw will not satisfy the
  audit");
- generic technique coaching at the pinecrest ceiling (next section).

**Never belongs in the handbook:**

- planted artifact names, account names, paths, or unit names;
- scored end-states ("all three profiles must be on");
- fix/mutation commands (`Set-SmbServerConfiguration …`, `chmod 644 …`,
  `systemctl disable x`);
- named verdicts ("the Print Spooler — a DC has no business printing");
- discovery keys — the fact that *is* the finding (the port an unasked-for
  console answers on);
- forensics answers, or hints that pin them to one artifact.

## The hint ceiling

When a box deserves a "Where to start" section, `boxes/pinecrest-hospital` is
the maximum: name **categories and standard tools**, never instances or
target values.

| Over the line (real, since fixed) | At the ceiling |
|---|---|
| "`Set-SmbServerConfiguration -EnableSMB1Protocol $false`" | "Windows Firewall profiles, SMB1 (`Get-SmbServerConfiguration`), UAC (`EnableLUA`)…" |
| "`Get-NetFirewallProfile` (all three must be on)" | "Windows Firewall profiles" |
| "the **Print Spooler** service (a DC has no business printing)" | "services a domain controller has no business running" |
| "services whose BinaryPathName is a PowerShell script… in `C:\ProgramData\Subsystems`" | "check what binary a service actually runs before trusting it" |
| "Something answering on **port 9090** is an admin web console" | "an admin web console nobody asked for — find it, remove it, confirm it went quiet" |

Tool names, standard tool syntax (`Get-*`, `auditpol`, `ss -tlnp`), generic
OS locations (the Run key's full path is fine), and inspection commands are
all legal. The player still chooses *where* to point them.

## The one-question test

Before sealing a box, walk the scorecard against the handbook and ask, for
every scored check: **could a player earn this check by copying the
handbook?** If yes, cut the answer back to the ceiling. This is the part no
lint can do: a prose spec-sheet with no commands and no planted names can
still hand over a scored end-state ("Allow TCP 80 on INPUT… INPUT, FORWARD and
OUTPUT to DROP") while passing every regex. The lint is a net, not a judge;
this walk is the judge.

## Where spoilers go instead

Detailed solutions belong in the per-check `solution:` field (see
`boxbuilder/README.md`). It ships in nothing — it renders only into the
post-event answer key (`python3 -m boxbuilder answer-key --scenario …`).
Progressive per-finding hints are the score report's `display:` strings. A fix
command in the handbook almost certainly belongs in `solution:` instead.

## The lint

`authoring/readme_lint.py` runs at compile time (`compile_scenario`), with two
severities:

- **Error** (blocks the compile): a forensics `answer`/`answers` value appears
  verbatim in the handbook. Values shorter than four characters, generic
  values (`true`, `none`, `password`…), answers the question text already
  prints, and values listed in `theme.readme_lint_allow` are skipped — the
  escape hatch for lenient aliases that collide with story vocabulary
  (static-pine's "nightcast").
- **Warnings** (printed during build as `[boxbuilder] WARNING: …`, carried in
  compile `--json` as `readme_warnings`):
  - a `solution:` line (at least 20 characters and three words) pasted
    verbatim into the handbook;
  - a mutation command in a code span or fence — PowerShell mutating verbs
    (`Set-`, `Stop-`, `Remove-`, `New-`, `Add-`, `Invoke-`, `Restart-`…) and
    anchored commands that change accounts, permissions, services, packages,
    firewalls, the registry, ACLs, or scheduled tasks (`chmod`, `userdel`,
    `systemctl stop|disable`, `apt remove`, `rm`, `ufw`, `iptables -A|-P`,
    `reg add`, `sc config`, `net user`, `auditpol /set`, `netsh`,
    `icacls /grant`, `schtasks /create`…). Inspection commands (`Get-*`, `ss`,
    `ps`, `reg query`, `auditpol /get`, `iptables -S`, `systemctl cat`) stay
    legal;
  - a planted absolute path that appears in a `solution:` *and* in the
    handbook — paths a check openly collects (crown jewels) and canonical OS
    locations are exempt, and a parent directory does not fire for a longer
    briefed path.

Run it directly:

```bash
python3 -m pytest tests/unit/test_authoring_readme_lint.py -q
```

A clean run on every box in-repo is enforced by the all-boxes regression
test; a new box with warnings needs an explicit fix (or a `readme_lint_allow`
entry, with a comment explaining why) before it merges.

## Formatting contract

One handbook per scenario. Content is authored as Markdown, rendered by two
renderers that share a subset — write to the intersection:

- Supported everywhere: `#`–`######` headings, `**bold**`, `*italic*`,
  accent `` `code` `` spans, `[text](url)` links, `-`/`1.` lists, `---` rules,
  fenced code blocks.
- Terminal-only: `>` blockquotes and `___` rules (the HTML page renders them
  literally).
- **No tables and no images in either renderer.** Use bold pseudo-headings
  and indented lines like chocolate-factory does.
- The file is embedded whole in the signed manifest: keep it under the
  64 KiB cap and expect it to be world-readable — one more reason it must
  not contain answers.
