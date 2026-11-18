"""Unit tests for the engine build identity (engine/build.py) and its
surface on the admin dashboard (engine/web.py) and admin API
(/admin/api/build route is exercised by the integration tier).
"""
import json
import time

import pytest

from engine import build, web

from tests.unit.test_web_pages import _comp


@pytest.fixture(autouse=True)
def _fresh_build_cache():
    build._CACHE = None
    yield
    build._CACHE = None


def test_build_info_parses_build_info_json(tmp_path):
    (tmp_path / "build_info.json").write_text(json.dumps({
        "commit": "1cf2444beefbeefbeefbeefbeefbeefbeefbeef",
        "built_at": "2026-11-18T01:12:00+00:00",
        "source": "bundle",
    }), encoding="utf-8")
    info = build.build_info(root=str(tmp_path))
    assert info["commit"] == "1cf2444beefbeefbeefbeefbeefbeefbeefbeef"
    assert info["built_at"] == "2026-11-18T01:12:00+00:00"
    assert info["source"] == "bundle"


def test_build_info_defaults_to_unknown_when_file_missing(tmp_path):
    info = build.build_info(root=str(tmp_path))
    assert info == {"commit": None, "built_at": None, "source": None}


def test_build_info_survives_corrupt_json(tmp_path):
    (tmp_path / "build_info.json").write_text("{not json", encoding="utf-8")
    assert build.build_info(root=str(tmp_path))["commit"] is None


def test_build_info_read_once_per_process(tmp_path):
    path = tmp_path / "build_info.json"
    path.write_text(json.dumps({"commit": "a" * 40}), encoding="utf-8")
    first = build.build_info(root=str(tmp_path))
    path.write_text(json.dumps({"commit": "b" * 40}), encoding="utf-8")
    assert build.build_info(root=str(tmp_path)) is first
    assert build.build_info(root=str(tmp_path), refresh=True)["commit"] == "b" * 40


def test_dashboard_shows_commit_when_build_known():
    web.engine_build._CACHE = {"commit": "c" * 40, "built_at": time.time(),
                               "source": "bundle"}
    html = web.admin_dashboard_page([_comp()], {}, csrf="t")
    assert "<code>ccccccc</code>" in html
    assert 'title="' + "c" * 40 + '"' in html
    assert "Engine build" in html


def test_dashboard_renders_an_iso_build_stamp_without_crashing():
    """The git deploy stamps built_at as ISO; _fmt_ts wants epoch floats."""
    web.engine_build._CACHE = {
        "commit": "e" * 40, "built_at": "2026-11-18T09:41:43+00:00",
        "source": "git"}
    html = web.admin_dashboard_page([_comp()], {}, csrf="t")
    assert "· built 2026-11-18 09:41" in html
    assert "<code>eeeeeee</code>" in html


def test_dashboard_says_unknown_for_dev_checkout():
    web.engine_build._CACHE = {"commit": None, "built_at": None,
                               "source": None}
    html = web.admin_dashboard_page([_comp()], {}, csrf="t")
    assert "Engine build unknown" in html
    assert "<code>" not in html


def test_build_line_is_outside_the_poll_div():
    web.engine_build._CACHE = {"commit": "d" * 40, "built_at": None,
                               "source": None}
    html = web.admin_dashboard_page([_comp()], {}, csrf="t")
    dash_end = html.index("</div>", html.index('id="dash"'))
    build_line = html.index("Engine build")
    assert build_line > dash_end > html.index('id="dash"')


def test_build_line_escapes_hostile_commit_field():
    web.engine_build._CACHE = {"commit": "<script>", "built_at": None,
                               "source": None}
    html = web.admin_dashboard_page([_comp()], {}, csrf="t")
    start = html.index("Engine build")
    line = html[html.rindex("<p", 0, start):html.index("</p>", start) + 4]
    assert "&lt;script&gt;" in line
    assert "<script>" not in line
