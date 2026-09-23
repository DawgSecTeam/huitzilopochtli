"""Regression tests for the whole-repo defect review fixes: ranked answer-key
redaction, transactional check-in, verify gating, engine server TLS/admin
input handling, confined adversary artifacts, root writes into user dirs,
in-process enrollment retry, and private boxbuilder staging."""
import base64
import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import threading
import time

import pytest

import engine.checkin as checkin_mod
from common.schema import (
    Bundle, Category, CollectorStatus, Evidence, Rubric, RubricEntry, SCHEMA_VERSION,
)
from common.version import AGENT_VERSION
from engine import server as server_mod
from engine import verify_gate
from engine.checkin import CheckinError, handle_checkin
from engine.enrollment import EnrollError, handle_enroll
from engine.store import Store


# --- helpers -------------------------------------------------------------------

@pytest.fixture
def store(tmp_path):
    return Store(str(tmp_path / "engine.sqlite3"))


def _evidence(check_id, raw, reason="collected"):
    return Evidence(
        check_id=check_id, check_type="t", host_id="h", status=CollectorStatus.OK,
        raw=raw, reason=reason, collected_monotonic=0.0, collected_wall_claim=0.0,
    )


def _bundle(evidence, seq=1):
    return Bundle(
        box_id="box-1", seq=seq, boot_id="boot", agent_version=AGENT_VERSION,
        scenario_name="sc", scenario_version=1, evidence=evidence,
        created_wall_claim=0.0, schema_version=SCHEMA_VERSION,
    )


def _secret_rubric():
    """One entry per expected-value-bearing matcher, every expected value
    carrying a SECRET marker so any leak is greppable."""
    def e(cid, matcher):
        return RubricEntry(check_id=cid, category=Category.VULN, matcher=matcher,
                           points=1, sla=None)
    return Rubric(schema_version=1, scenario_name="sc", scenario_version=1, entries=[
        e("eq", {"tag": "equals", "value": "SECRET_EQ"}),
        e("neq", {"tag": "not_equals", "value": "SECRET_NEQ"}),
        e("ct", {"tag": "contains", "value": "SECRET_CT"}),
        e("re", {"tag": "regex", "pattern": "SECRET_RE"}),
        e("ua", {"tag": "user_absent", "username": "SECRET_USER"}),
        e("up", {"tag": "user_present", "username": "SECRET_UP"}),
        e("grp", {"tag": "group_members_subset_of", "group": "wheel",
                  "allowed": ["SECRET_MEMBER"]}),
        e("ans", {"tag": "answer_equals", "value": "SECRET_ANS"}),
    ])


def _failing_evidence():
    return [
        _evidence("eq", {"matched": "x"}),
        _evidence("neq", {"matched": "SECRET_NEQ"}, reason=""),
        _evidence("ct", {"matched": "x"}),
        _evidence("re", {"matched": "x"}),
        _evidence("ua", {"users": ["SECRET_USER"]}, reason=""),
        _evidence("up", {"users": []}),
        _evidence("grp", {"group_members": {"wheel": ["mallory"]}}),
        _evidence("ans", {"answer": "wrong"}),
    ]


@pytest.fixture
def enrolled(store, monkeypatch):
    store.create_box("box-1", base64.b64encode(b"k" * 32).decode(), "sc", 1)
    monkeypatch.setattr(verify_gate, "verify", lambda pk, msg, sig: True)
    return store


# --- 1. ranked responses never carry the answer key --------------------------------

def test_checkin_response_redacts_expected_values(enrolled):
    resp = handle_checkin(enrolled, _bundle(_failing_evidence()), b"sig",
                          _secret_rubric(), b"secret", [])
    wire = json.dumps(server_mod._jsonable(resp))
    # SECRET_NEQ / SECRET_USER were sent BY the box, but their evidence
    # reasons are blank, so they may only reappear via the matcher reason.
    assert "SECRET" not in wire, wire
    by_id = {r.check_id: r for r in resp.score.results}
    assert by_id["eq"].reason == "collected"
    assert by_id["eq"].passed is False


def test_checkin_500_body_omits_exception_text(store, monkeypatch):
    class _Boom(Exception):
        pass

    def _raise(*a, **k):
        raise _Boom("rubric expected SECRET_VALUE")

    monkeypatch.setattr(server_mod, "handle_checkin", _raise)
    body = json.dumps(server_mod._jsonable(_bundle([]))).encode()
    store.save_scenario("sc", json.dumps({"scenario_name": "sc", "entries": []}),
                        json.dumps({}))
    status, payload = _serve_once(store, "POST", "/checkin", body)
    assert status == 500
    assert "SECRET" not in payload


# --- 7. check-in is all-or-nothing ---------------------------------------------------

def test_checkin_failure_rolls_back_seq_and_audit(enrolled, monkeypatch):
    def _boom(*a, **k):
        raise RuntimeError("malformed stored matcher")

    monkeypatch.setattr(checkin_mod, "evaluate", _boom)
    with pytest.raises(RuntimeError):
        handle_checkin(enrolled, _bundle([], seq=5), b"sig", _secret_rubric(),
                       b"secret", [])
    box = enrolled.get_box("box-1")
    assert box.last_seq == 0
    assert box.t0 is None
    count = enrolled._conn.execute("SELECT COUNT(*) FROM checkins").fetchone()[0]
    assert count == 0

    # The agent's retry of the same bundle is now scored, not a 409 replay.
    monkeypatch.undo()
    monkeypatch.setattr(verify_gate, "verify", lambda pk, msg, sig: True)
    resp = handle_checkin(enrolled, _bundle([], seq=5), b"sig", _secret_rubric(),
                          b"secret", [])
    assert resp.last_seq == 5


def test_store_atomic_nests_and_rolls_back(store):
    with pytest.raises(ValueError):
        with store.atomic():
            store.create_token("t1", "sc", time.time() + 60)
            with store.atomic():
                store.create_token("t2", "sc", time.time() + 60)
            raise ValueError
    assert store.get_token("t1") is None and store.get_token("t2") is None
    with store.atomic():
        store.create_token("t3", "sc", time.time() + 60)
    assert store.get_token("t3") is not None


# --- 5. signature verification can't be reached cheaply or unboundedly ----------------

def _enroll_body(token):
    return {
        "enrollment_token": token, "box_id": "box-9",
        "public_key": base64.b64encode(b"k" * 32).decode(),
        "agent_version": AGENT_VERSION, "scenario_name": "sc", "scenario_version": 1,
    }


@pytest.mark.parametrize("setup,status", [
    (lambda s: None, 400),                                           # unknown
    (lambda s: s.create_token("tok", "sc", time.time() - 1), 410),   # expired
    (lambda s: (s.create_token("tok", "sc", time.time() + 60),
                s.consume_token("tok")), 409),                       # consumed
])
def test_enroll_rejects_bad_token_before_verifying(store, monkeypatch, setup, status):
    calls = []
    monkeypatch.setattr(verify_gate, "verify", lambda *a: calls.append(a) or True)
    setup(store)
    with pytest.raises(EnrollError) as exc:
        handle_enroll(store, _enroll_body("tok"), b"sig")
    assert exc.value.status_code == status
    assert calls == []


def test_saturated_verify_gate_maps_to_503(store, monkeypatch):
    gate = threading.BoundedSemaphore(1)
    gate.acquire()  # every slot busy
    monkeypatch.setattr(verify_gate, "_GATE", gate)
    assert verify_gate.verify(b"k" * 32, b"m", b"s") is None

    store.create_box("box-1", base64.b64encode(b"k" * 32).decode(), "sc", 1)
    with pytest.raises(CheckinError) as exc:
        handle_checkin(store, _bundle([]), b"sig", _secret_rubric(), b"s", [])
    assert exc.value.status_code == 503

    store.create_token("tok", "sc", time.time() + 60)
    with pytest.raises(EnrollError) as exc:
        handle_enroll(store, _enroll_body("tok"), b"sig")
    assert exc.value.status_code == 503


# --- 4 / 8. engine HTTP server --------------------------------------------------------

def _start_server(store, ssl_ctx=None, max_conns=8, admin_token="adm"):
    server_mod.Handler.store = store
    server_mod.Handler.admin_token = admin_token
    server_mod.Handler.server_secret = b"s"
    httpd = server_mod._EngineHTTPServer(("127.0.0.1", 0), server_mod.Handler,
                                         ssl_ctx=ssl_ctx, max_conns=max_conns)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def _serve_once(store, method, path, body=b"", headers=None):
    httpd = _start_server(store)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", httpd.server_address[1], timeout=10)
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        return resp.status, resp.read().decode()
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_admin_token_non_ascii_header_is_403_not_crash(store):
    status, _ = _serve_once(store, "POST", "/admin/tokens", b"{}",
                            {"X-HUITZILOPOCHTLI-Admin-Token": "caf\xe9"})
    assert status == 403


@pytest.mark.parametrize("ttl", ["Infinity", "NaN", "-5", "0"])
def test_admin_tokens_rejects_non_finite_or_nonpositive_ttl(store, ttl):
    body = ('{"scenario_name": "sc", "ttl_s": %s}' % ttl).encode()
    status, _ = _serve_once(store, "POST", "/admin/tokens", body,
                            {"X-HUITZILOPOCHTLI-Admin-Token": "adm"})
    assert status == 400


@pytest.mark.skipif(shutil.which("openssl") is None, reason="needs openssl")
def test_idle_tls_client_does_not_block_other_requests(store, tmp_path):
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=localhost", "-keyout", str(key), "-out", str(cert)],
        check=True, capture_output=True,
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    httpd = _start_server(store, ssl_ctx=ctx)
    port = httpd.server_address[1]
    idle = socket.create_connection(("127.0.0.1", port))  # never handshakes
    try:
        client_ctx = ssl._create_unverified_context()
        conn = http.client.HTTPSConnection("127.0.0.1", port, context=client_ctx,
                                           timeout=5)
        conn.request("GET", "/health")
        assert conn.getresponse().status == 200
    finally:
        idle.close()
        httpd.shutdown()
        httpd.server_close()


def test_connections_beyond_cap_are_closed(store):
    httpd = _start_server(store, max_conns=1)
    port = httpd.server_address[1]
    hog = socket.create_connection(("127.0.0.1", port))  # holds the only slot
    try:
        time.sleep(0.2)
        second = socket.create_connection(("127.0.0.1", port), timeout=5)
        second.sendall(b"GET /health HTTP/1.0\r\n\r\n")
        assert second.recv(100) == b""  # closed without service
        second.close()
    finally:
        hog.close()
        httpd.shutdown()
        httpd.server_close()


# --- 3. adversary artifacts never follow symlinks ---------------------------------------

@pytest.mark.skipif(os.name == "nt", reason="POSIX confinement path")
def test_drop_inert_artifact_refuses_symlinks(tmp_path, monkeypatch):
    from agent.adversary.actions import ACTIONS

    base = tmp_path / "base"
    base.mkdir(mode=0o700)
    victim = tmp_path / "victim"
    victim.write_text("precious")
    (base / "marker.txt").symlink_to(victim)
    (base / "sub").symlink_to(tmp_path)
    monkeypatch.setenv("HUITZILOPOCHTLI_ARTIFACT_DIR", str(base))

    ACTIONS["drop_inert_artifact"]({"path": "marker.txt"}, None)
    ACTIONS["drop_inert_artifact"]({"path": "sub/victim"}, None)
    ACTIONS["drop_inert_artifact"]({"path": "a/../../victim"}, None)
    assert victim.read_text() == "precious"

    ACTIONS["drop_inert_artifact"]({"path": "nested/ok.txt"}, None)
    assert (base / "nested" / "ok.txt").read_text().startswith("HUITZILOPOCHTLI")


@pytest.mark.skipif(os.name == "nt", reason="POSIX confinement path")
def test_drop_inert_artifact_refuses_group_writable_base(tmp_path, monkeypatch):
    from agent.adversary.actions import ACTIONS

    base = tmp_path / "base"
    base.mkdir()
    base.chmod(0o777)
    monkeypatch.setenv("HUITZILOPOCHTLI_ARTIFACT_DIR", str(base))
    ACTIONS["drop_inert_artifact"]({"path": "m.txt"}, None)
    assert not (base / "m.txt").exists()


# --- 2. root writes into user dirs go through the owner ---------------------------------

@pytest.mark.skipif(os.name == "nt" or os.geteuid() != 0, reason="needs root")
def test_forensics_template_as_root_does_not_follow_planted_symlink(tmp_path):
    import agent.__main__ as agent_main

    home = tmp_path / "home"
    home.mkdir()
    os.chown(home, 65534, 65534)
    victim = tmp_path / "victim"
    victim.write_text("root-owned")
    (home / "Forensics-Questions.txt.tmp").symlink_to(victim)
    os.lchown(home / "Forensics-Questions.txt.tmp", 65534, 65534)
    tmp_path.chmod(0o755)

    agent_main._write_forensics_template(str(home / "Forensics-Questions.txt"),
                                         [(1, "q?")])
    assert victim.read_text() == "root-owned"
    assert os.stat(victim).st_uid == 0
    assert os.stat(home / "Forensics-Questions.txt").st_uid == 65534


@pytest.mark.skipif(os.name == "nt", reason="POSIX")
def test_forensics_template_non_root_path_unchanged(tmp_path):
    import agent.__main__ as agent_main

    path = tmp_path / "Forensics-Questions.txt"
    agent_main._write_forensics_template(str(path), [(1, "q?")])
    assert "Q1: q?" in path.read_text()


# --- 9. enrollment failures retry in-process ------------------------------------------

def test_run_ranked_retries_enrollment_instead_of_exiting(tmp_path, monkeypatch):
    import agent.__main__ as agent_main
    import agent.identity

    class _Stop(Exception):
        pass

    attempts, sleeps = [], []

    def _enroll(*a):
        attempts.append(1)
        if len(attempts) == 1:
            raise Exception("enrollment failed: HTTP 410 (enrollment token expired)")
        return True

    def _collect(checks, ctx):
        raise _Stop

    class _Cfg:
        identity_path = str(tmp_path / "identity.json")
        checkin_interval_s = 30

    identity = agent.identity.Identity(box_id="b", private_key=b"x" * 32,
                                       public_key=b"y" * 32, last_seq=0)
    monkeypatch.setattr(agent_main.agent.identity, "load_or_create", lambda p: identity)
    monkeypatch.setattr(agent_main, "_ensure_enrolled", _enroll)
    monkeypatch.setattr(agent_main.time, "sleep", sleeps.append)
    monkeypatch.setattr(agent_main.agent.collector, "run_all", _collect)

    with pytest.raises(_Stop):
        agent_main._run_ranked(_Cfg(), type("M", (), {"checks": []})(), ctx=None)
    assert len(attempts) == 2
    assert sleeps == [60]


# --- 10. boxbuilder stages root installs privately ------------------------------------

class _StageHandle:
    addr = "10.0.0.1"

    def __init__(self, stdout, rc=0):
        self.stdout, self.rc, self.runs = stdout, rc, []

    def run(self, cmd, *, timeout=1800, sudo=True):
        from boxbuilder.providers.base import RunResult
        self.runs.append((cmd, sudo))
        return RunResult(exit_status=self.rc, stdout=self.stdout, stderr="")


def test_stage_path_uses_one_private_mktemp_dir():
    from boxbuilder.providers.base import stage_path

    h = _StageHandle("/tmp/huitzilopochtli-stage.Xy12ab\n")
    assert stage_path(h, "a.service") == "/tmp/huitzilopochtli-stage.Xy12ab/a.service"
    assert stage_path(h, "b.sh") == "/tmp/huitzilopochtli-stage.Xy12ab/b.sh"
    assert h.runs == [("mktemp -d /tmp/huitzilopochtli-stage.XXXXXX", False)]


@pytest.mark.parametrize("stdout,rc", [("", 1), ("/etc\n", 0)])
def test_stage_path_refuses_unexpected_mktemp_output(stdout, rc):
    from boxbuilder.providers.base import stage_path

    with pytest.raises(RuntimeError):
        stage_path(_StageHandle(stdout, rc), "x")


# --- at-least-once adversary directive delivery ----------------------------------------

_POOL = [{"id": "e1", "action": "flush_firewall", "window_s": [0, 0]}]


def test_engine_resends_every_issued_directive(enrolled):
    first = handle_checkin(enrolled, _bundle([], seq=1), b"sig", _secret_rubric(),
                           b"s", _POOL)
    assert [d.event_id for d in first.directives] == ["e1"]
    assert [d.event_id for d in first.issued_directives] == ["e1"]

    # Suppose the first response never reached the box: the next check-in
    # no longer carries e1 as new, but still re-sends it.
    second = handle_checkin(enrolled, _bundle([], seq=2), b"sig", _secret_rubric(),
                            b"s", _POOL)
    assert second.directives == []
    assert [(d.event_id, d.action) for d in second.issued_directives] == [
        ("e1", "flush_firewall")]


def test_transport_parses_issued_directives_and_tolerates_old_engines():
    from agent.transport import _parse_checkin_response

    base = {"server_time": 1.0, "score": {}, "next_checkin_s": 60, "last_seq": 3,
            "directives": []}
    assert _parse_checkin_response(dict(base)).issued_directives == []
    resp = _parse_checkin_response(dict(base, issued_directives=[
        {"event_id": "e1", "action": "kill_service", "params": {"service": "x"}}]))
    assert [(d.event_id, d.params) for d in resp.issued_directives] == [
        ("e1", {"service": "x"})]


def test_transport_keeps_directives_from_flushed_queue(tmp_path, monkeypatch):
    """After an outage the first queued bundle's response carries the due
    directive; the fresh bundle's response (returned) must still include it."""
    import agent.transport as transport
    from common.schema import Directive

    queue = tmp_path / "q"
    queue.write_text('{"queued":1}\n')
    sent = []

    class _Resp:
        def __init__(self, directives):
            self.directives = directives

    def _send(self, body):
        sent.append(body)
        return _Resp([Directive("e1", "flush_firewall", {})] if len(sent) == 1 else [])

    monkeypatch.setattr(transport.TransportClient, "_send_canonical", _send)

    class _Id:
        private_key, box_id = b"", "b"

    resp = transport.TransportClient("http://x", _Id(), str(queue)).checkin(
        _bundle([], seq=2))
    assert len(sent) == 2
    assert [d.event_id for d in resp.directives] == ["e1"]


def _directive_response(new=(), issued=()):
    from common.schema import Directive
    mk = lambda i: Directive(event_id=i, action="flush_firewall", params={})
    return type("R", (), {"directives": [mk(i) for i in new],
                          "issued_directives": [mk(i) for i in issued]})()


def test_agent_runs_each_event_id_once_across_resends(tmp_path, monkeypatch):
    import agent.__main__ as agent_main

    ran = []
    monkeypatch.setattr(agent_main.agent.adversary.executor, "execute",
                        lambda d, ctx: ran.append(d.event_id))
    ident = str(tmp_path / "identity.json")

    agent_main._run_directives(_directive_response(new=["e1"], issued=["e1"]), ident, None)
    agent_main._run_directives(_directive_response(issued=["e1", "e2"]), ident, None)
    agent_main._run_directives(_directive_response(issued=["e1", "e2"]), ident, None)
    assert ran == ["e1", "e2"]
    assert json.loads((tmp_path / "identity.json.directives").read_text()) == ["e1", "e2"]


def test_agent_records_failed_directive_so_it_is_not_retried(tmp_path, monkeypatch):
    import agent.__main__ as agent_main

    calls = []

    def _fail(d, ctx):
        calls.append(d.event_id)
        raise RuntimeError("unknown adversary action")

    monkeypatch.setattr(agent_main.agent.adversary.executor, "execute", _fail)
    ident = str(tmp_path / "identity.json")
    for _ in range(2):
        agent_main._run_directives(_directive_response(issued=["e9"]), ident, None)
    assert calls == ["e9"]


def test_agent_runs_nothing_when_executed_record_is_corrupt(tmp_path, monkeypatch):
    import agent.__main__ as agent_main

    ran = []
    monkeypatch.setattr(agent_main.agent.adversary.executor, "execute",
                        lambda d, ctx: ran.append(d.event_id))
    (tmp_path / "identity.json.directives").write_text("{not json")
    agent_main._run_directives(_directive_response(issued=["e1"]),
                               str(tmp_path / "identity.json"), None)
    assert ran == []
