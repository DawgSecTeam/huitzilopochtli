"""Render tests: the debrief PDF is produced and sane."""

from __future__ import annotations

import re
import zlib

import pytest

from debrief.digest import build_digest
from debrief.render import render_pdf
from tests.helpers import make_db


def _digest(tmp_path):
    return build_digest(make_db(tmp_path))[0]


def _pdf_text(raw: bytes) -> bytes:
    """Content-stream bytes, decompressed where fpdf2 flate-compressed them."""
    chunks = [raw]
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", raw, re.S):
        try:
            chunks.append(zlib.decompress(m.group(1)))
        except zlib.error:
            chunks.append(m.group(1))
    return b"\n".join(chunks)


def test_pdf_renders(tmp_path):
    out = tmp_path / "debrief.pdf"
    render_pdf(_digest(tmp_path), out)
    raw = out.read_bytes()
    assert raw.startswith(b"%PDF")
    assert b"%%EOF" in raw[-64:]


def test_pdf_carries_team_name(tmp_path):
    digest = _digest(tmp_path)
    name = digest["team"]["display_name"]
    out = tmp_path / "debrief.pdf"
    render_pdf(digest, out)
    text = _pdf_text(out.read_bytes())
    assert name.encode("latin-1") in text


def test_pdf_splits_caught_and_missed(tmp_path):
    digest = _digest(tmp_path)
    checks = digest["team"]["checks"]
    solved = next(c["id"] for c in checks if c["solved"])
    missed = next(c["id"] for c in checks if not c["solved"])
    out = tmp_path / "debrief.pdf"
    render_pdf(digest, out)
    text = _pdf_text(out.read_bytes())
    assert b"Caught" in text and b"Missed" in text
    assert solved.encode() in text and missed.encode() in text


