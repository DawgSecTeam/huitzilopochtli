"""Unit tests for the 7 check plugins under agent/checks/.

Each check's collect(spec, ctx) contract:
- file_regex: collect_params {"path": str, "extract": str}; raw {"matched": str|None, "present": bool}
- permission: collect_params {"path": str}; raw {"mode": str|None, "uid": int|None, "gid": int|None, "exists": bool|None}
- user_group: collect_params {}; raw {"users": list[str]|None, "group_members": dict|None}
- service_state: collect_params {"service": str}; raw {"active": bool, "enabled": bool}; needs PlatformContext
- package: collect_params {"package": str}; raw {"installed": bool, "version": str|None}; needs PlatformContext
- http_uptime: collect_params {"url": str}; raw {"status": int|None, "body": str, "error": str|None}
- db_query: collect_params {"host": str, "port": int}; raw {"ok": bool, "error": str|None}
"""
import http.server
import os
import socket
import threading
import time

import pytest

from agent.checks.db_query import DbQueryCheck
from agent.checks.file_regex import FileRegexCheck
from agent.checks.http_uptime import HttpUptimeCheck
from agent.checks.package import PackageCheck
from agent.checks.permission import PermissionCheck
from agent.checks.service_state import ServiceStateCheck
from agent.checks.user_group import UserGroupCheck
from agent.platform.base import PlatformContext
from common.schema import Category, CheckSpec, CollectorStatus, Evidence


def make_spec(check_type, collect_params, timeout_s=2.0):
    return CheckSpec(
        id="chk-1",
        type=check_type,
        category=Category.VULN,
        host_id="host-1",
        collect_params=collect_params,
        display_title="test check",
        display_max_points=10,
        timeout_s=timeout_s,
    )


def assert_well_formed(ev):
    assert isinstance(ev, Evidence)
    assert isinstance(ev.status, CollectorStatus)
    assert isinstance(ev.raw, dict)
    assert isinstance(ev.reason, str) and ev.reason
    assert isinstance(ev.collected_monotonic, float)
    assert isinstance(ev.collected_wall_claim, float)


# --- file_regex --------------------------------------------------------------

def test_file_regex_matches(tmp_path):
    f = tmp_path / "sshd_config"
    f.write_text("Port 22\nPermitRootLogin yes\n")
    spec = make_spec("file_regex", {"path": str(f), "extract": r"PermitRootLogin (\w+)"})
    ev = FileRegexCheck().collect(spec, None)
    assert_well_formed(ev)
    assert ev.status == CollectorStatus.OK
    assert ev.raw == {"matched": "yes", "present": True}


def test_file_regex_no_match(tmp_path):
    f = tmp_path / "config"
    f.write_text("nothing relevant here\n")
    spec = make_spec("file_regex", {"path": str(f), "extract": r"PermitRootLogin (\w+)"})
    ev = FileRegexCheck().collect(spec, None)
    assert_well_formed(ev)
    assert ev.status == CollectorStatus.OK
    assert ev.raw == {"matched": None, "present": True}


def test_file_regex_missing_file(tmp_path):
    missing = tmp_path / "does_not_exist.conf"
    spec = make_spec("file_regex", {"path": str(missing), "extract": r"(\w+)"})
    ev = FileRegexCheck().collect(spec, None)
    assert_well_formed(ev)
    assert ev.status == CollectorStatus.ERROR
    assert ev.raw == {"matched": None, "present": False}


# --- permission ----------------------------------------------------------------

def test_permission_existing_file(tmp_path):
    f = tmp_path / "secret"
    f.write_text("hi")
    os.chmod(f, 0o640)
    spec = make_spec("permission", {"path": str(f)})
    ev = PermissionCheck().collect(spec, None)
    assert_well_formed(ev)
    assert ev.status == CollectorStatus.OK
    assert ev.raw["exists"] is True
    assert ev.raw["mode"] == "0640"
    assert ev.raw["uid"] == os.getuid()
    assert ev.raw["gid"] == os.getgid()


def test_permission_nonexistent_path_is_ok(tmp_path):
    # Per permission.py's docstring/contract: a nonexistent path is a valid OK
    # observation (absence of a file is itself informative), not an ERROR.
    missing = tmp_path / "nope"
    spec = make_spec("permission", {"path": str(missing)})
    ev = PermissionCheck().collect(spec, None)
    assert_well_formed(ev)
    assert ev.status == CollectorStatus.OK
    assert ev.raw == {"mode": None, "uid": None, "gid": None, "exists": False}


# --- user_group ------------------------------------------------------------------

def test_user_group_parses_real_files():
    spec = make_spec("user_group", {})
    ev = UserGroupCheck().collect(spec, None)
    assert_well_formed(ev)
    assert ev.status == CollectorStatus.OK
    assert isinstance(ev.raw["users"], list)
    assert isinstance(ev.raw["group_members"], dict)
    assert len(ev.raw["users"]) > 0


def test_user_group_custom_passwd_file(tmp_path, monkeypatch):
    passwd = tmp_path / "passwd"
    passwd.write_text("root:x:0:0:root:/root:/bin/bash\nbackdoor:x:1000:1000::/home/backdoor:/bin/sh\n")
    group = tmp_path / "group"
    group.write_text("wheel:x:10:root,backdoor\n")

    # user_group.py hardcodes /etc/passwd and /etc/group paths, so exercise
    # the parsing helpers directly rather than monkeypatching the module.
    import agent.checks.user_group as ug_mod
    users = ug_mod._parse_passwd(str(passwd))
    groups = ug_mod._parse_group(str(group))
    assert users == ["root", "backdoor"]
    assert groups == {"wheel": ["root", "backdoor"]}


def test_user_group_missing_passwd_file(monkeypatch):
    import agent.checks.user_group as ug_mod

    def fake_parse_passwd(path="/etc/passwd"):
        raise OSError("no such file")

    monkeypatch.setattr(ug_mod, "_parse_passwd", fake_parse_passwd)
    spec = make_spec("user_group", {})
    ev = UserGroupCheck().collect(spec, None)
    assert_well_formed(ev)
    assert ev.status == CollectorStatus.ERROR
    assert ev.raw == {"users": None, "group_members": None}


# --- service_state / package: mock PlatformContext ------------------------------

class MockPlatformContext(PlatformContext):
    """Minimal stub PlatformContext for testing checks that need one."""

    def __init__(self, services=None, packages=None, raise_on_service=False, raise_on_package=False):
        self._services = services or {}  # name -> (active, enabled)
        self._packages = packages or {}  # name -> (installed, version)
        self._raise_on_service = raise_on_service
        self._raise_on_package = raise_on_package

    def service_active(self, name):
        if self._raise_on_service:
            raise RuntimeError("systemctl not found")
        return self._services.get(name, (False, False))[0]

    def service_enabled(self, name):
        if self._raise_on_service:
            raise RuntimeError("systemctl not found")
        return self._services.get(name, (False, False))[1]

    def package_installed(self, name):
        if self._raise_on_package:
            raise RuntimeError("package manager not found")
        return self._packages.get(name, (False, None))


def test_service_state_known_service():
    ctx = MockPlatformContext(services={"sshd": (True, True)})
    spec = make_spec("service_state", {"service": "sshd"})
    ev = ServiceStateCheck().collect(spec, ctx)
    assert_well_formed(ev)
    assert ev.status == CollectorStatus.OK
    assert ev.raw == {"active": True, "enabled": True}


def test_service_state_unknown_service_defaults_inactive():
    ctx = MockPlatformContext(services={"sshd": (True, True)})
    spec = make_spec("service_state", {"service": "nonexistent-service"})
    ev = ServiceStateCheck().collect(spec, ctx)
    assert_well_formed(ev)
    assert ev.status == CollectorStatus.OK
    assert ev.raw == {"active": False, "enabled": False}


def test_service_state_ctx_raises_degrades_to_error():
    ctx = MockPlatformContext(raise_on_service=True)
    spec = make_spec("service_state", {"service": "sshd"})
    ev = ServiceStateCheck().collect(spec, ctx)
    assert_well_formed(ev)
    assert ev.status == CollectorStatus.ERROR
    assert ev.raw == {"active": False, "enabled": False}


def test_package_installed():
    ctx = MockPlatformContext(packages={"openssh-server": (True, "1:9.3p1-1")})
    spec = make_spec("package", {"package": "openssh-server"})
    ev = PackageCheck().collect(spec, ctx)
    assert_well_formed(ev)
    assert ev.status == CollectorStatus.OK
    assert ev.raw == {"installed": True, "version": "1:9.3p1-1"}


def test_package_not_installed():
    ctx = MockPlatformContext(packages={"openssh-server": (True, "1:9.3p1-1")})
    spec = make_spec("package", {"package": "some-unknown-pkg"})
    ev = PackageCheck().collect(spec, ctx)
    assert_well_formed(ev)
    assert ev.status == CollectorStatus.OK
    assert ev.raw == {"installed": False, "version": None}


def test_package_ctx_raises_degrades_to_error():
    ctx = MockPlatformContext(raise_on_package=True)
    spec = make_spec("package", {"package": "openssh-server"})
    ev = PackageCheck().collect(spec, ctx)
    assert_well_formed(ev)
    assert ev.status == CollectorStatus.ERROR
    assert ev.raw == {"installed": False, "version": None}


# --- http_uptime: real HTTPServer in a background thread -------------------------

class _OkHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"hello world")

    def log_message(self, format, *args):
        pass  # silence test output


@pytest.fixture
def http_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _OkHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_http_uptime_success(http_server):
    port = http_server
    spec = make_spec("http_uptime", {"url": f"http://127.0.0.1:{port}/"}, timeout_s=2.0)
    ev = HttpUptimeCheck().collect(spec, None)
    assert_well_formed(ev)
    assert ev.status == CollectorStatus.OK
    assert ev.raw["status"] == 200
    assert ev.raw["body"] == "hello world"
    assert ev.raw["error"] is None


def test_http_uptime_connection_refused():
    # Port 1 is a privileged, essentially-never-listening port; connection
    # should be refused immediately (no hang) on 127.0.0.1.
    spec = make_spec("http_uptime", {"url": "http://127.0.0.1:1/"}, timeout_s=1.0)
    ev = HttpUptimeCheck().collect(spec, None)
    assert_well_formed(ev)
    assert ev.status == CollectorStatus.ERROR
    assert ev.raw["status"] is None
    assert ev.raw["body"] == ""
    assert ev.raw["error"] is not None


# --- db_query: real socket probes -------------------------------------------------

@pytest.fixture
def open_socket():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        yield port
    finally:
        srv.close()


def test_db_query_open_port(open_socket):
    port = open_socket
    spec = make_spec("db_query", {"host": "127.0.0.1", "port": port}, timeout_s=2.0)
    ev = DbQueryCheck().collect(spec, None)
    assert_well_formed(ev)
    assert ev.status == CollectorStatus.OK
    assert ev.raw == {"ok": True, "error": None}


def test_db_query_closed_port():
    # Bind-and-immediately-close to get a port that is very likely to refuse
    # connections deterministically (nothing else can grab it in this window).
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    spec = make_spec("db_query", {"host": "127.0.0.1", "port": port}, timeout_s=1.0)
    ev = DbQueryCheck().collect(spec, None)
    assert_well_formed(ev)
    # db_query.py's contract: a refused connection is still a successful
    # *probe* (OK status) carrying ok=False in raw, not a CollectorStatus.ERROR.
    assert ev.status == CollectorStatus.OK
    assert ev.raw["ok"] is False
    assert ev.raw["error"] is not None
