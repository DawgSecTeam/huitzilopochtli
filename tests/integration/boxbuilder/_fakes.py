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
        else:
            # install_box now resolves the connecting user's uid:gid (id -u; id -g)
            # so it can chown the install dir for non-root SSH users; give it a
            # plausible uid:gid by default.
            if "id -u" in cmd and "id -g" in cmd:
                out, rc = "1000\n1000", 0
        from boxbuilder.providers.base import RunResult
        return RunResult(exit_status=rc, stdout=out, stderr="")

    def put(self, local, remote, mode=None):
        self.puts.append((local, remote, mode))

    def install_init(self, kind, mode="honor"):
        self.init_kind = kind
        self.init_mode = mode

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


def install_fake_vulndb_cli(tmp_path, monkeypatch, *, initial=None):
    """Install a fake `python3 -m vulndb_cli` with persistent catalog state.

    Handles `list --json`, `create --file -`, and `upload <ref> <file>` — the commands
    boxbuilder/vulndb.py uses — persisting to a JSON state file so separate subprocess
    invocations see each other's writes. Sets $VULNDB_CLI_DIR. Returns the state-file path
    (a Path) so tests can assert on catalog contents.
    """
    vdir = tmp_path / "vulndb-cli"
    pkg = vdir / "vulndb_cli"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "cli.py").write_text("# marker for resolve_vulndb_cli_dir\n")
    state_file = tmp_path / "vulndb_state.json"
    state_file.write_text(json.dumps({"configurations": initial or [], "next_id": 0}))

    template = textwrap.dedent("""\
        import json, os, sys
        STATE = {STATE}
        def _load():
            with open(STATE) as f:
                return json.load(f)
        def _save(s):
            with open(STATE, "w") as f:
                json.dump(s, f)
        clean, skip = [], False
        for a in sys.argv[1:]:
            if skip:
                skip = False; continue
            if a == "--url":
                skip = True; continue
            if a == "--yes":
                continue
            clean.append(a)
        cmd = clean[0] if clean else ""
        s = _load()
        if cmd == "list":
            print(json.dumps(s["configurations"]))
        elif cmd == "create":
            defn = json.load(sys.stdin)
            if any(c["name"] == defn["name"] for c in s["configurations"]):
                print("duplicate name", file=sys.stderr); sys.exit(1)
            s["next_id"] += 1
            row = dict(defn, id=s["next_id"], attachments=[])
            s["configurations"].append(row); _save(s); print(json.dumps(row))
        elif cmd == "upload":
            ref, path = clean[1], clean[2]
            name = os.path.basename(path)
            for c in s["configurations"]:
                if str(c.get("id")) == ref or c.get("name") == ref:
                    att = {"id": len(c.get("attachments", [])) + 1, "configuration_id": c["id"],
                           "original_name": name, "size_bytes": os.path.getsize(path)}
                    c.setdefault("attachments", []).append(att)
                    _save(s); print(json.dumps(att)); sys.exit(0)
            print("no such config", file=sys.stderr); sys.exit(1)
        elif cmd == "get":
            ref = clean[1]
            for c in s["configurations"]:
                if str(c.get("id")) == ref or c.get("name") == ref:
                    print(json.dumps(c)); sys.exit(0)
            sys.exit(1)
        else:
            sys.exit(1)
    """).replace("{STATE}", json.dumps(str(state_file)))
    (pkg / "__main__.py").write_text(template)
    monkeypatch.setenv("VULNDB_CLI_DIR", str(vdir))
    return state_file
