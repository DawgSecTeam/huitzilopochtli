"""Unit tests for boxbuilder.vulndb against a fake vulndb-cli (a generated, stateful
`python3 -m vulndb_cli`) — no real vulndb-ui/MySQL/MinIO needed.

boxbuilder/vulndb.py now shells out to vulndb-cli instead of doing raw HTTP, so the test double
is a fake CLI package (install_fake_vulndb_cli) rather than a fake HTTP server. It exercises
ensure_configuration/ensure_attachment's idempotency and content-addressing logic offline.
"""
import json

import pytest

from boxbuilder import vulndb
from tests.integration.boxbuilder._fakes import install_fake_vulndb_cli


@pytest.fixture
def fake_vulndb(tmp_path, monkeypatch):
    """Install the fake vulndb-cli; yield (base_url, state_file_path). base_url is ignored by
    the fake but threaded through so resolve_vulndb_url stays in the call path."""
    monkeypatch.delenv("VULNDB_UI_URL", raising=False)
    state_file = install_fake_vulndb_cli(tmp_path, monkeypatch)
    yield "http://fake.invalid", state_file


def _state(state_file):
    return json.loads(state_file.read_text())


_DEFINITION = {
    "name": "theme-motd", "description": "test", "platform": "linux",
    "category": "misconfiguration", "type": "command", "run_as": "root",
    "script": "#!/bin/sh\nexit 0\n", "depends_on": [],
}


def test_resolve_vulndb_url_precedence(monkeypatch):
    monkeypatch.delenv("VULNDB_UI_URL", raising=False)
    assert vulndb.resolve_vulndb_url() == "http://127.0.0.1:3000"
    monkeypatch.setenv("VULNDB_UI_URL", "http://10.0.0.5:3000")
    assert vulndb.resolve_vulndb_url() == "http://10.0.0.5:3000"
    assert vulndb.resolve_vulndb_url("http://explicit:9000") == "http://explicit:9000"


def test_resolve_vulndb_cli_dir_missing_raises(monkeypatch, tmp_path):
    # Point VULNDB_CLI_DIR at an empty dir so neither candidate matches.
    monkeypatch.setenv("VULNDB_CLI_DIR", str(tmp_path / "nope"))
    with pytest.raises(vulndb.VulndbError, match="vulndb-cli repo not found"):
        vulndb.resolve_vulndb_cli_dir()


def test_load_seed_definition_all_four_present():
    for name in ("theme-wallpaper", "theme-motd", "theme-readme", "theme-shortcuts"):
        d = vulndb.load_seed_definition(name)
        assert d["name"] == name
        assert d["type"] == "command"
        assert d["run_as"] == "root"
        assert d["script"].startswith("#!/bin/sh")


def test_list_configurations_empty(fake_vulndb):
    base_url, _ = fake_vulndb
    assert vulndb.list_configurations(base_url) == []


def test_create_configuration(fake_vulndb):
    base_url, _ = fake_vulndb
    row = vulndb.create_configuration(base_url, _DEFINITION)
    assert row["id"] == 1
    assert row["name"] == "theme-motd"


def test_ensure_configuration_idempotent(fake_vulndb):
    base_url, state_file = fake_vulndb
    c1 = vulndb.ensure_configuration(base_url, _DEFINITION)
    c2 = vulndb.ensure_configuration(base_url, _DEFINITION)
    assert c1["id"] == c2["id"]
    assert len(_state(state_file)["configurations"]) == 1


def test_ensure_configuration_never_overwrites_existing(fake_vulndb):
    base_url, state_file = fake_vulndb
    vulndb.ensure_configuration(base_url, _DEFINITION)
    modified = dict(_DEFINITION, script="#!/bin/sh\necho different\n")
    vulndb.ensure_configuration(base_url, modified)
    state = _state(state_file)
    assert len(state["configurations"]) == 1
    assert state["configurations"][0]["script"] == _DEFINITION["script"]


def test_ensure_attachment_uploads_and_returns_content_addressed_filename(fake_vulndb, tmp_path):
    base_url, _ = fake_vulndb
    config = vulndb.ensure_configuration(base_url, vulndb.load_seed_definition("theme-wallpaper"))
    f = tmp_path / "wallpaper.png"
    f.write_bytes(b"some wallpaper bytes")

    filename = vulndb.ensure_attachment(base_url, config, str(f))
    assert filename.endswith("-wallpaper.png")
    assert len(filename.split("-", 1)[0]) == 16  # sha256[:16] prefix


def test_ensure_attachment_idempotent_same_content(fake_vulndb, tmp_path):
    base_url, _ = fake_vulndb
    config = vulndb.ensure_configuration(base_url, vulndb.load_seed_definition("theme-wallpaper"))
    f = tmp_path / "wallpaper.png"
    f.write_bytes(b"identical bytes")

    filename1 = vulndb.ensure_attachment(base_url, config, str(f))
    # Re-fetch the row (as boxbuilder/theme.py would across compiles) so the second call
    # sees the attachment the first call just created.
    refreshed = vulndb.list_configurations(base_url)
    row = [c for c in refreshed if c["name"] == "theme-wallpaper"][0]
    filename2 = vulndb.ensure_attachment(base_url, row, str(f))

    assert filename1 == filename2
    assert len(row["attachments"]) == 1


def test_ensure_attachment_different_content_uploads_new(fake_vulndb, tmp_path):
    base_url, _ = fake_vulndb
    config = vulndb.ensure_configuration(base_url, vulndb.load_seed_definition("theme-wallpaper"))
    f1 = tmp_path / "a.png"
    f1.write_bytes(b"content one")
    f2 = tmp_path / "b.png"
    f2.write_bytes(b"content two, totally different")

    name1 = vulndb.ensure_attachment(base_url, config, str(f1))
    refreshed = vulndb.list_configurations(base_url)
    row = [c for c in refreshed if c["name"] == "theme-wallpaper"][0]
    name2 = vulndb.ensure_attachment(base_url, row, str(f2))

    assert name1 != name2
    refreshed2 = vulndb.list_configurations(base_url)
    row2 = [c for c in refreshed2 if c["name"] == "theme-wallpaper"][0]
    assert len(row2["attachments"]) == 2
