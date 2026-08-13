"""Unit tests for boxbuilder.vulndb against a minimal fake vulndb-ui (stdlib
http.server, in-process) -- no real vulndb-ui/MySQL/MinIO needed to run these.

The real wire-format compatibility (multipart upload field name, response shapes) was
additionally verified live against a real vulndb-ui during development; this fake server
exists to exercise ensure_configuration/ensure_attachment's idempotency logic offline.
"""
import http.server
import json
import re
import threading

import pytest

from boxbuilder import vulndb


class _FakeVulndbHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass  # silence request logging in test output

    def _send_json(self, status, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/configurations":
            self._send_json(200, self.server.state["configurations"])
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        state = self.server.state

        if self.path == "/api/configurations":
            definition = json.loads(raw.decode("utf-8"))
            if any(c["name"] == definition["name"] for c in state["configurations"]):
                self._send_json(500, {"error": f"Duplicate entry '{definition['name']}'"})
                return
            state["next_id"] += 1
            row = {**definition, "id": state["next_id"]}
            state["configurations"].append(row)
            self._send_json(201, row)
            return

        m = re.match(r"^/api/configurations/(\d+)/attachments$", self.path)
        if m:
            config_id = int(m.group(1))
            match = re.search(rb'filename="([^"]*)"', raw)
            filename = match.group(1).decode("utf-8") if match else "unknown"
            for c in state["configurations"]:
                if c["id"] == config_id:
                    c.setdefault("attachments", [])
                    attachment = {
                        "id": len(c["attachments"]) + 1, "configuration_id": config_id,
                        "original_name": filename, "mime_type": "application/octet-stream",
                        "size_bytes": len(raw),
                    }
                    c["attachments"].append(attachment)
                    self._send_json(201, attachment)
                    return
            self._send_json(404, {"error": "no such configuration"})
            return

        self._send_json(404, {"error": "not found"})


@pytest.fixture
def fake_vulndb_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _FakeVulndbHandler)
    server.state = {"configurations": [], "next_id": 0}
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    try:
        yield base_url, server.state
    finally:
        server.shutdown()
        thread.join(timeout=5)


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


def test_load_seed_definition_all_four_present():
    for name in ("theme-wallpaper", "theme-motd", "theme-readme", "theme-shortcuts"):
        d = vulndb.load_seed_definition(name)
        assert d["name"] == name
        assert d["type"] == "command"
        assert d["run_as"] == "root"
        assert d["script"].startswith("#!/bin/sh")


def test_unreachable_url_raises_vulndberror():
    with pytest.raises(vulndb.VulndbError, match="could not reach vulndb-ui"):
        vulndb.list_configurations("http://127.0.0.1:1", timeout=2)


def test_list_configurations_empty(fake_vulndb_server):
    base_url, _ = fake_vulndb_server
    assert vulndb.list_configurations(base_url) == []


def test_create_configuration(fake_vulndb_server):
    base_url, _ = fake_vulndb_server
    row = vulndb.create_configuration(base_url, _DEFINITION)
    assert row["id"] == 1
    assert row["name"] == "theme-motd"


def test_ensure_configuration_idempotent(fake_vulndb_server):
    base_url, state = fake_vulndb_server
    c1 = vulndb.ensure_configuration(base_url, _DEFINITION)
    c2 = vulndb.ensure_configuration(base_url, _DEFINITION)
    assert c1["id"] == c2["id"]
    assert len(state["configurations"]) == 1


def test_ensure_configuration_never_overwrites_existing(fake_vulndb_server):
    base_url, state = fake_vulndb_server
    vulndb.ensure_configuration(base_url, _DEFINITION)
    modified = dict(_DEFINITION, script="#!/bin/sh\necho different\n")
    vulndb.ensure_configuration(base_url, modified)
    assert len(state["configurations"]) == 1
    assert state["configurations"][0]["script"] == _DEFINITION["script"]


def test_ensure_attachment_uploads_and_returns_content_addressed_filename(
    fake_vulndb_server, tmp_path,
):
    base_url, _ = fake_vulndb_server
    config = vulndb.ensure_configuration(base_url, vulndb.load_seed_definition("theme-wallpaper"))
    f = tmp_path / "wallpaper.png"
    f.write_bytes(b"some wallpaper bytes")

    filename = vulndb.ensure_attachment(base_url, config, str(f))
    assert filename.endswith("-wallpaper.png")
    assert len(filename.split("-", 1)[0]) == 16  # sha256[:16] prefix


def test_ensure_attachment_idempotent_same_content(fake_vulndb_server, tmp_path):
    base_url, _ = fake_vulndb_server
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


def test_ensure_attachment_different_content_uploads_new(fake_vulndb_server, tmp_path):
    base_url, _ = fake_vulndb_server
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
