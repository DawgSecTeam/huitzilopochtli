"""Shared test doubles for boxbuilder integration tests.

Lives in a regular module (NOT conftest.py) so tests can import it by name
without colliding with pytest's conftest-collection resolution (a bare
`from conftest import X` can resolve to an unrelated conftest.py elsewhere in
the tree depending on collection order).

The fixtures wrapping these (fake_provider, fake_provider_factory) live in
conftest.py.
"""
import json
import textwrap


class FakeHandle:
    """Records all calls; run() returns canned results keyed by a substring."""

    def __init__(self, name, addr, user, password, port=22):
        self.name = name
        self.addr = addr
        self.user = user
        self.password = password
        self.port = port
        self.runs = []        # list of cmd strings
        self.puts = []        # list of (local, remote, mode)
        self.init_kind = None
        self.exported = None
        self._run_replies = {}  # substring -> (stdout, exit_status)

    def set_run_reply(self, substr, stdout="", exit_status=0):
        self._run_replies[substr] = (stdout, exit_status)

    def run(self, cmd, *, timeout=1800, sudo=True):
        self.runs.append(cmd)
        out, rc = "", 0
        for substr, (s, r) in self._run_replies.items():
            if substr in cmd:
                out, rc = s, r
                break
        from boxbuilder.providers.base import RunResult
        return RunResult(exit_status=rc, stdout=out, stderr="")

    def put(self, local, remote, mode=None):
        self.puts.append((local, remote, mode))

    def install_init(self, kind):
        self.init_kind = kind

    def export(self, out_path, fmt="ova"):
        self.exported = (out_path, fmt)
        from boxbuilder.providers.base import ExportResult
        return ExportResult(mode="wrote", path=out_path, format=fmt)

    def close(self):
        pass


class FakeProvider:
    """Provider that hands out a FakeHandle. Records start/stop."""

    def __init__(self):
        self.name = "fake"
        self.started_cfg = None
        self.last_handle = None

    def start(self, cfg):
        self.started_cfg = dict(cfg)
        self.last_handle = FakeHandle(
            name=cfg.get("name", "box"),
            addr=cfg.get("host", "10.0.0.99"),
            user=cfg.get("user", "u"),
            password=cfg.get("password", "p"),
            port=cfg.get("port", 22),
        )
        return self.last_handle

    def stop(self, handle):
        handle.close()


def install_fake_nakon(tmp_path, monkeypatch, *, build_json=None, deploy_json=None):
    """Install a fake `python3 -m nakon` whose `build --json` / `deploy --json`
    print canned JSON. Either may be None to leave that command's output empty."""
    ndir = tmp_path / "nakon"
    pkg = ndir / "nakon"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "cli.py").write_text("# marker for resolve_nakon_dir\n")
    build_blob = json.dumps(build_json) if build_json is not None else "null"
    deploy_blob = json.dumps(deploy_json) if deploy_json is not None else "null"
    (pkg / "__main__.py").write_text(textwrap.dedent(f"""\
        import sys, json
        cmd = sys.argv[1] if len(sys.argv) > 1 else ""
        if cmd == "build":
            print({build_blob!r})
        elif cmd == "deploy":
            print({deploy_blob!r})
        sys.exit(0)
    """))
    monkeypatch.setenv("NAKON_DIR", str(ndir))
    return str(ndir)
