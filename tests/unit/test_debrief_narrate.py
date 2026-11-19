"""Narration tests: what the model may and may not put in the debrief."""

from __future__ import annotations

import pytest

from debrief import narrate as narrate_mod
from debrief.digest import build_digest
from tests.helpers import make_db


@pytest.fixture()
def digest(tmp_path):
    return build_digest(make_db(tmp_path))[0]


def test_model_output_used(digest):
    text = ('{"summary": "Strong run, clean availability.",'
            ' "why_matters": [{"id": "recipe_private", "text": "kept the box on the'
            ' allowlist"}], "focus": ["watch the red team"],'
            ' "assessment": "Good posture.", "protocol": "Keep it up."}')
    out = narrate_mod.narrate(digest, model="test", transport=lambda *a, **kw: text)
    assert out["summary"].startswith("Strong run")
    assert out["why_matters"][0]["id"] == "recipe_private"


def test_model_output_rejected_on_digits(digest):
    text = ('{"summary": "Solved 3 checks.",'
            ' "why_matters": [{"id": "banner", "text": "missed one"}],'
            ' "focus": [], "assessment": "ok", "protocol": "ok"}')
    out = narrate_mod.narrate(digest, model="test", transport=lambda *a, **kw: text)
    # digit-bearing prose never survives validation -> template fallback
    assert "Solved 3 checks" not in out["summary"]


def test_model_output_rejected_on_unknown_check(digest):
    text = ('{"summary": "All good.", "why_matters": [{"id": "missing_id",'
            ' "text": "nothing"}], "focus": [], "assessment": "ok",'
            ' "protocol": "ok"}')
    out = narrate_mod.narrate(digest, model="test", transport=lambda *a, **kw: text)
    assert "missing_id" not in out["summary"]


def test_fallback_narrative(tmp_path):
    digest = build_digest(make_db(tmp_path))[0]
    out = narrate_mod.narrate(digest, model=None)
    assert out["summary"]
    assert "why_matters" in out


def test_empty_digest_handled():
    """No facts is a valid state (e.g. an empty competition); narration
    must not crash on it."""
    out = narrate_mod.narrate({"team": {}, "feedback_pool": []},
                              transport=lambda *a, **kw: "{}")
    assert out == {} or out["summary"]


def test_garbage_digest_handled():
    """Garbage in -> template narration out, no raise."""
    out = narrate_mod.narrate({"team": {"score": {"total": 0}}},
                              transport=lambda *a, **kw: "{not json")
    assert out["summary"]
