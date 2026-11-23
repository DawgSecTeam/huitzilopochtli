"""Entry point for the debrief tool.

    python3 -m debrief --db <engine.db> [--out DIR] [--model NAME]

Read-only over the engine db; writes one PDF per competition team plus the
digest the report was rendered from. No engine code runs beyond the digest
reader; nothing is scored, mutated, or pushed.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from debrief.digest import build_digest
from debrief.narrate import DEFAULT_LLM_URL, narrate
from debrief.render import render_pdf


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    digests = build_digest(Path(args.db), args.competition)
    if args.players is not None:
        digests = [d for d in digests
                   if (d.get("team", {}).get("display_name") or "").lower()
                   in args.players]
    if not digests:
        print("no competitions found; nothing to report", flush=True)
        return 1

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    def _one(digest_row: dict) -> None:
        digest_row["narration"] = narrate(
            digest_row,
            model=args.model,
            url=args.llm_url,
            api_key=args.api_key,
        )
        pdf_path = Path(args.out) / f"{_slug(digest_row)}.pdf"
        render_pdf(digest_row, pdf_path)
        print(f"wrote {pdf_path}", flush=True)

    workers = max(1, args.jobs)
    if workers == 1:
        for digest_row in digests:
            _one(digest_row)
    else:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for _ in pool.map(_one, digests):
                pass
    return 0


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="debrief",
        description="Generate post-event PDF debriefs from an engine store.",
    )
    parser.add_argument("--db", required=True,
                        help="path to the engine SQLite database")
    parser.add_argument("--competition", default=None,
                        help="competition slug (default: all in the store)")
    parser.add_argument("--player", default=None,
                        help="only this team's display name (repeat ignored, "
                             "comma-separated list accepted)")
    parser.add_argument("--out", default="debrief-out",
                        help="output directory for the PDF reports")
    parser.add_argument("--model", default=None,
                        help="chat model name; omitting it renders the "
                             "digest without coaching prose")
    parser.add_argument("--llm-url", default=None,
                        help="OpenAI-compatible chat endpoint "
                             "(default %s or $DEBRIEF_LLM_URL)" % DEFAULT_LLM_URL)
    parser.add_argument("--jobs", type=int, default=None,
                        help="narrations to run concurrently (default 3)")
    parser.add_argument("--api-key", default=None,
                        help="bearer token for the endpoint "
                             "(default $DEBRIEF_LLM_API_KEY)")
    args = parser.parse_args(argv)
    args.llm_url = args.llm_url or os.environ.get("DEBRIEF_LLM_URL")
    args.api_key = args.api_key or os.environ.get("DEBRIEF_LLM_API_KEY")
    args.players = ({p.strip().lower()
                     for p in args.player.split(",") if p.strip()}
                    if args.player else None)
    args.jobs = args.jobs if args.jobs is not None else 3
    return args


def _slug(digest_row: dict) -> str:
    team = (digest_row.get("team") or {}).get("display_name") or "team"
    comp = (digest_row.get("competition") or {}).get("slug") or "run"
    return f"{comp}-{team}".replace(" ", "-").lower()
