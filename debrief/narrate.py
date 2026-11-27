"""Narration for the debrief tool.

Authority bounds, enforced in this order:

1.  The model only ever sees facts this module put in the prompt: the
    fact card is pruned of solution content (expect values, walkthrough
    text) before it leaves, so there is nothing secret to leak out.
2.  The model may pick which provided facts to talk about (why_matters,
    focus, next_time) and phrase them -- but every fact it can name came
    from the card, so its choices change emphasis, never reality.
3.  Its output passes _validate() before it can touch the PDF. Every text
    field must be digit-free (numbers belong to the tables, which are
    deterministic), length-capped, and structurally shaped; anything that
    fails is dropped in favour of the template text.

No path from here can alter a score, a check result, or the uptime the
tables show. The model is a voice on the report, not a source in it.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any, Callable, Optional

DEFAULT_LLM_URL = "http://127.0.0.1:11434/v1/chat/completions"

MAX_SUMMARY = 600          # "what happened" prose
MAX_WHY_TEXT = 450         # per why-matters item
MAX_WHY = 3                # how many why-matters items a debrief keeps
MAX_FOCUS = 3              # items
MAX_FOCUS_TEXT = 240       # per focus item
MAX_NEXT_TIME = 3          # items
MAX_NEXT_TIME_TEXT = 180   # per item
MAX_ASSESSMENT = 500
MAX_PROTOCOL = 180

_DIGIT_RE = re.compile(r"[0-9]")


class NarrationError(Exception):
    """The local model's answer did not satisfy the narration contract."""


# --- prompt ------------------------------------------------------------------


def _fact_card(digest: dict) -> dict:
    """The fields the model may see, and nothing else.

    The digest is pruned here: expect values, matcher details and reason
    strings never leave this module, and the card carries only what a coach
    needs to comment on.
    """
    comp = digest.get("competition", {})
    field = digest.get("field", {})
    team = digest.get("team", {})

    def _check_summary(c: dict) -> dict:
        return {
            "id": c.get("id"),
            "title": c.get("title"),
            "category": c.get("category"),
            "solved": bool(c.get("solved")),
        }

    pool = [
        {"id": p.get("id"), "kind": p.get("kind"), "title": p.get("title")}
        for p in digest.get("feedback_pool", [])
    ]
    return {
        "competition": {
            "name": comp.get("name"),
            "players_total": field.get("players_total"),
        },
        "team": {
            "display_name": team.get("display_name"),
            "members": team.get("members") or [],
            "rank": team.get("rank"),
            "rank_total": team.get("rank_total"),
            "score_total": (team.get("score") or {}).get("total"),
            "checks_solved": len(
                [c for c in team.get("checks", []) if c.get("solved")]
            ),
            "checks_total": len(team.get("checks") or []),
            "services": [
                {
                    "check_id": s.get("check_id"),
                    "state": s.get("state"),
                    "accrued_points": s.get("accrued_points"),
                }
                for s in team.get("services", [])
            ],
            "incidents": [
                {
                    "event_id": i.get("event_id"),
                    "action": i.get("action"),
                    "restored": bool(i.get("restored")),
                }
                for i in team.get("incidents", [])
            ],
            "misses": [
                _check_summary(c)
                for c in team.get("checks", []) if not c.get("solved")
            ],
        },
        "pool": pool,
    }


def build_messages(digest: dict) -> list[dict]:
    card = _fact_card(digest)
    system = (
        "You are a supportive coach debriefing a team after a hands-on "
        "security-hardening practice round. You will receive one JSON fact "
        "card of verified run facts: final scores and placement, the checks "
        "the team solved or missed with points lost, availability figures "
        "per service, and red-team incident outcomes. Everything in the "
        "card is a fact you may rely on.\n"
        "Write a short debrief (at most 220 words) for the team as your own "
        "message, purely in prose (no markdown, no bullet lists, no code "
        "fences), with this shape:\n"
        "- One opening line naming what the run showed (its headline "
        "strengths and its single clearest gap).\n"
        '- A "why these mattered" passage: for up to three of the misses '
        "in the card, one short sentence each on the general practice "
        "behind it. Use the card's own ids to anchor which item you mean, "
        "and keep every sentence true of any similar team.\n"
        '- A "what to work on next time" list: up to three items drawn '
        "from the card, each one short sentence.\n"
        "- One closing line about procedure and spirit only, addressed to "
        "nobody in particular.\n"
        "Rules you must follow:\n"
        "- Use ONLY the facts in the card. Never invent a check, a number, "
        "a service name, or a scenario detail, and never name a specific "
        "configuration value, file path or command: the numbers on the "
        "page are rendered by the report engine from the card, and a digit "
        "in your prose is a sign you have started guessing.\n"
        "- Keep the guidance general and transferable enough to be honest: "
        "say what the practice is, not what this box was.\n"
        "Reply with one JSON object with exactly these keys: \"summary\" "
        "(one prose paragraph, at most 600 characters, no digits), "
        '"why_matters" (a list of at most 3 objects {"id": <card id>, '
        '"text": one sentence, no digits}), "focus" (a list of at most 3 '
        "short strings, each no digits), \"assessment\" (at most 500 "
        "characters, no digits), and \"protocol\" (at most 180 characters, "
        "no digits). No markdown, no code fences, no trailing text."
    )
    user = json.dumps(card, ensure_ascii=False)
    return (
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    )


# --- the model call ----------------------------------------------------------


def narrate(digest: dict, *, model: Optional[str] = None,
            url: Optional[str] = None, api_key: Optional[str] = None,
            timeout_s: float = 180.0,
            transport: Optional[Callable] = None) -> dict:
    """Generate the coaching prose for one digest; always renderable.

    The return value is complete and validated: callers never branch on
    model state, they render whatever this hands them.
    """
    if not model:
        return _fallback(digest, reason="no model configured")
    api_key = api_key or os.environ.get("DEBRIEF_LLM_API_KEY")
    call = transport or _default_transport
    messages = build_messages(digest)
    options = {"model": model, "api_key": api_key, "timeout_s": timeout_s}
    try:
        text = call(messages, options, url or DEFAULT_LLM_URL)
    except Exception as exc:  # noqa: BLE001 -- degrade, never block the PDF
        return _fallback(digest, reason=f"model call failed: {exc}")
    try:
        return _validate(json.loads(_strip_reasoning(text)), digest)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        return _fallback(digest, reason=f"model output rejected: {exc}")


def _strip_reasoning(text: str) -> str:
    """Drop reasoning-model scaffolding: qwen3-style think blocks (the
    model's scratch space, not its answer) and any wrapper prose around
    the JSON object."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    text = re.sub(r"<think>.*", "", text, flags=re.DOTALL)  # unclosed
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        return text[start:end + 1]
    return text.strip()


_RETRY_CODES = {500, 502, 503, 504, 524, 529}


def _default_transport(messages: list[dict], options: dict,
                       url: str) -> str:
    """One streaming chat completion against an OpenAI-compatible endpoint,
    retried with backoff on the transient failures the endpoint actually
    shows (edge 5xx, gateway resets). Validation and fallback stay as they
    are: retries only buy connection odds, never output leniency."""
    last: Exception = NarrationError("LLM transport never ran")
    for attempt in range(3):
        try:
            return _stream_once(messages, options, url)
        except NarrationError as exc:
            last = exc
            transient = getattr(exc, "transient", True)
            if not transient:
                raise
            if attempt < 2:
                import time
                time.sleep(2.0 * (attempt + 1))
    raise last


def _stream_once(messages: list[dict], options: dict, url: str) -> str:
    """One streaming chat completion against an OpenAI-compatible endpoint.

    Streamed on purpose: reasoning models can spend minutes before the
    answer starts, and edges in front of the proxy kill idle connections
    (the 524s) — streamed chunks keep the connection demonstrably alive
    and let the read timeout apply per chunk, not per generation."""
    body = {
        "model": options.get("model", ""),
        "messages": messages,
        "temperature": 0.3,
        "max_tokens": 4000,
        "stream": True,
    }
    headers = {
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
        # the default urllib user-agent is blocked at some edges (403 at a
        # proxy that answers curl fine); name the client instead
        "User-Agent": "huitzilopochtli-debrief/1.0",
    }
    api_key = options.get("api_key")
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    content_parts: list[str] = []
    reasoning_parts: list[str] = []
    try:
        with urllib.request.urlopen(
                req, timeout=options.get("timeout_s", 180.0)) as resp:
            for raw_line in resp:
                line = raw_line.decode("utf-8", "replace").strip()
                if not line.startswith("data:"):
                    continue
                payload = line[len("data:"):].strip()
                if not payload or payload == "[DONE]":
                    continue
                try:
                    chunk = json.loads(payload)
                except json.JSONDecodeError:
                    continue
                choices = chunk.get("choices") or []
                if not choices:
                    continue
                delta = choices[0].get("delta") or {}
                piece = delta.get("content")
                if isinstance(piece, str):
                    content_parts.append(piece)
                thought = delta.get("reasoning_content")
                if isinstance(thought, str):
                    reasoning_parts.append(thought)
    except urllib.error.HTTPError as exc:
        retry = exc.code in _RETRY_CODES
        err = NarrationError(f"LLM endpoint unreachable: {exc}")
        err.transient = retry
        raise err from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise NarrationError(f"LLM endpoint unreachable: {exc}") from exc

    content = "".join(content_parts)
    if not content.strip():
        # some reasoning deployments only surface the answer inside the
        # reasoning trace when the visible channel stays empty
        content = "".join(reasoning_parts)
    if not content.strip():
        raise NarrationError("LLM response content is empty")
    return content


# --- validation --------------------------------------------------------------


def _validate(obj: Any, digest: dict) -> dict:
    """Structural gate between model output and the printed page.

    Every text field is stripped to plain prose, capped, and checked by the
    one rule that matters in a debrief: no digits. A field that fails its
    rule is dropped, never repaired -- the renderer shows the deterministic
    sentence for that slot instead.
    """
    if not isinstance(obj, dict):
        raise NarrationError("model output is not a JSON object")
    out: dict = {}
    for key in ("summary", "assessment", "protocol"):
        text = obj.get(key)
        out[key] = _prose(text, max_len=_TEXT_CAP[key]) if _prose_gate(text) else ""

    why = obj.get("why_matters")
    kept = []
    if isinstance(why, list):
        pool_ids = {p.get("id") for p in digest.get("feedback_pool", [])}
        for item in why:
            if not isinstance(item, dict):
                continue
            if item.get("id") not in pool_ids:
                continue
            text = item.get("text")
            if not _prose_gate(text):
                continue
            kept.append({"id": item["id"], "text": _prose(text, max_len=MAX_WHY_TEXT)})
    out["why_matters"] = kept[:MAX_WHY]

    focus, next_time = obj.get("focus"), obj.get("next_time")
    out["focus"] = _list_texts(focus, MAX_FOCUS, MAX_FOCUS_TEXT)
    out["next_time"] = _list_texts(next_time, MAX_NEXT_TIME, MAX_NEXT_TIME_TEXT)
    return out


_TEXT_CAP = {
    "summary": MAX_SUMMARY,
    "why_matters": MAX_WHY_TEXT,
    "focus": MAX_FOCUS_TEXT,
    "next_time": MAX_NEXT_TIME_TEXT,
    "assessment": MAX_ASSESSMENT,
    "protocol": MAX_PROTOCOL,
}


def _list_texts(items: Any, cap: int, max_len: int) -> list[str]:
    if not isinstance(items, list):
        return []
    out = []
    for item in items:
        text = _prose(item, max_len=max_len)
        if text and _prose_gate(text):
            out.append(text)
        if len(out) >= cap:
            break
    return out


def _prose_gate(text: Any) -> bool:
    """A text field may pass when it is prose at all and carries no
    digits; anything else fails closed for that slot."""
    if not isinstance(text, str):
        return False
    return bool(text.strip()) and not _DIGIT_RE.search(text)


def _prose(text: Any, max_len: int) -> str:
    """Normalise any incoming string to renderable ASCII prose."""
    if not isinstance(text, str):
        return ""
    cleaned = text.replace("\u2018", "'").replace("\u2019", "'")
    cleaned = cleaned.replace("\u201c", '"').replace("\u201d", '"')
    cleaned = "".join(c for c in cleaned if ord(c) >= 32 or c == "\n")
    return " ".join(cleaned.split())[:max_len]


# --- the model-less path ---------------------------------------------------------


def _fallback(digest: dict, reason: str = "") -> dict:
    """The no-model debrief: every statement derived from the digest's own
    facts, no model in the loop. The report stays complete and honest —
    strengths, misses and focus items are computed, only the prose polish
    is missing."""
    team = digest.get("team", {})
    checks = team.get("checks", []) or []
    solved = [c for c in checks if c.get("solved")]
    missed = [c for c in checks if not c.get("solved")]

    strengths, focus = _group_facts(solved, missed)
    score = team.get("score") or {}
    minutes = team.get("run_minutes") or 0
    checkins = team.get("checkin_count") or 0
    parts = []
    if solved:
        parts.append(f"Solved {len(solved)} of {len(checks)} scored checks")
    elif checks:
        parts.append("No scored checks were solved in this run")
    if missed:
        parts.append(
            f"{len(missed)} checks remained unsolved, led by "
            f"{missed[0].get('id')}"
        )
    if minutes and minutes < 5:
        parts.append(
            f"the box reported for only {checkins} check-ins over "
            f"{minutes} minutes, so this reads as a stub run"
        )
    summary = "; ".join(parts) + "." if parts else (
        "No scored checks recorded for this run."
    )
    if reason:
        summary += f" (Narration note: {reason}.)"

    why = [
        {"id": p.get("id"), "text": _why_line(p)}
        for p in (digest.get("feedback_pool") or [])[:MAX_WHY]
    ]
    return {
        "summary": summary,
        "why_matters": why,
        "focus": focus,
        "assessment": ("; ".join(strengths) + ".") if strengths else "",
        "protocol": "",
    }


def _group_facts(solved: list, missed: list) -> tuple:
    """Deterministic strengths and focus items from check lists.

    Grouping rule: forensics (fq-) and service (svc_) ids are their own
    groups; a check id of the form <section>_<n> groups by its section
    prefix (scenarios bake their structure into ids); anything else groups
    by category. A group is a strength when every check in it was solved;
    it is a focus item when checks remain unsolved — with points on the
    table only when the run's rubric is still in the store."""
    groups: dict[str, dict] = {}
    for check in solved + missed:
        cid = check.get("id") or ""
        if cid.startswith("fq-"):
            key = "forensics"
        elif cid.startswith("svc_"):
            key = "services"
        else:
            match = re.match(r"^([a-zA-Z]+\d+)_", cid)
            key = match.group(1) if match else (check.get("category") or "unscored")
        group = groups.setdefault(key, {"solved": 0, "missed": 0, "lost": 0})
        if check.get("solved"):
            group["solved"] += 1
        else:
            group["missed"] += 1
            group["lost"] += check.get("max_points") or 0

    labels = {
        "forensics": "forensics questions",
        "services": "scored services",
        "vuln": "hardening checks",
        "penalty": "required-state checks",
        "prohibited": "prohibited-item checks",
        "unscored": "unscored checks",
    }
    strengths, focus = [], []
    for key, group in sorted(groups.items()):
        label = labels.get(key, f"{key} checks")
        total = group["solved"] + group["missed"]
        if group["missed"] == 0 and group["solved"]:
            strengths.append(f"all {group['solved']} {label}")
        elif group["solved"] and total and group["solved"] / total >= 0.8:
            strengths.append(
                f"{label} mostly solved ({group['solved']} of {total})"
            )
        if group["missed"]:
            points = (f", {group['lost']} points on the table"
                      if group["lost"] else "")
            focus.append((
                f"Revisit {label}: {group['missed']} unresolved{points}",
                group["missed"],
            ))
    focus.sort(key=lambda item: -item[1])
    return strengths, [text for text, _ in focus[:4]]


def _why_line(entry: dict) -> str:
    titles = {
        "hardening": "a hardening check left unsolved",
        "uptime": "service uptime points left on the table",
        "incident": "a red-team event that was never restored",
    }
    points = entry.get("points_lost")
    amount = f", worth about {points} points" if points else ""
    return f"{titles.get(entry.get('kind'), 'a scoring opportunity')}{amount}"
