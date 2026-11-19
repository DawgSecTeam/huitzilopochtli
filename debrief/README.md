# Debrief reports — post-competition team PDFs

One PDF per team: what the run showed, what the team did well, and what to
work on. All numbers come from the scoring engine's own store at report
time; nothing here re-scores, re-weights, or re-derives a run fact.

```
engine db ──>  digest (facts)  ──>  PDF (render)
                    │
                    └──>  narration (LLM; optional)
```

## Reading the report

| Section | Source |
|---|---|
| Score summary | `scores` table: per-check verdicts, per-service availability |
| Check table | `scores.score_json` results, one row per check |
| Availability | `checkins` bundle evidence + `sla_state` ledger rows |
| Red-team events | `adversary_log` rows |
| Narration | the local model's reading of the same facts (below) |

## Running

```bash
python3 -m debrief --db /path/to/engine.db --out debrief-out
```

Types of output:

- `debrief.pdf` — the debrief itself, one per team in the competition.
- `digest.json` — the fact card the debrief was rendered from (for
  review, diffing, and re-renders).

Optional model: set `HUITZ_DEBRIEF_LLM` to a local OpenAI-compatible
endpoint (e.g. an Ollama/HF model server) to have the tool narrate *why*
a miss mattered. No model required:

```bash
HUITZ_DEBRIEF_LLM=http://127.0.0.1:11434/v1/chat/completions \
  python3 -m debrief --db /path/to/engine.db
```

## Narration contract (why it's safe)

The narrator reads one fact card (all numbers, all names, all timelines)
and writes prose. It never grades, never invents a check, and never
touches a fact the engine did not compute: the report's tables and
verdicts are rendered *before* the model contributes anything, and the
model's own output is constrained to narrative commentary on the facts.
If the model is unreachable, the score and check tables still render --
the fallback is a plain-English listing of what was solved and what was
missed, not an empty page.
