"""The Windows click-to-join launcher (packaging/huitz-join-win.pyw).

Loaded by path, not importable as a module: a `.pyw` is a Windows artifact and
the repo's package boundary (agent/ + common/ ship in the zipapp) must not
grow a GUI dependency. Everything here is the logic around the form — the
elevation decision, the code normalization, and the rule that the real join is
`agent/join.py`'s, never a copy of it. The tkinter window itself is stubbed.
"""
import importlib.util
from importlib.machinery import SourceFileLoader
import json
import os
import sys
import types

import pytest

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
LAUNCHER = os.path.join(_REPO_ROOT, "packaging", "huitz-join-win.pyw")


@pytest.fixture(scope="module")
def gui():
    # `.pyw` is not a suffix importlib knows, so load it as an explicit source
    # file — the extension is the only Windows-ness in the file's name.
    loader = SourceFileLoader("huitz_join_win", LAUNCHER)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class _FakeJoinModule:
    """Stands in for the `agent.join` imported out of the installed zipapp."""

    def __init__(self, result=None, error=None, start_error=None):
        self.result = result or {"player_name": "Ada",
                                "competition_name": "Invite",
                                "run_ends_at": 1_800_000_000}
        self.error = error
        self.start_error = start_error
        self.calls = []

        class _E(Exception):
            pass

        self.JoinError = _E
        if error:
            self._boom = _E(error)

        join_mod = self

        def join(config_path, code, start_service=True):
            join_mod.calls.append((config_path, code, start_service))
            if join_mod.error:
                raise join_mod._boom
            return join_mod.result

        def _start_agent():
            if join_mod.start_error:
                raise join_mod.JoinError(join_mod.start_error)
        self.join = join
        self._start_agent = _start_agent


@pytest.fixture
def fake_join(gui, monkeypatch):
    def install(**kw):
        fake = _FakeJoinModule(**kw)
        monkeypatch.setattr(gui, "_load_agent", lambda: (fake, None, None))
        return fake
    return install


def test_the_launcher_is_shipped_where_the_installer_expects_it(gui):
    # boxbuilder/providers/ssh.py SFTPs this exact file into the install dir.
    assert os.path.isfile(LAUNCHER)
    assert gui.LAUNCHER_NAME == os.path.basename(LAUNCHER)


def test_code_is_normalized_exactly_like_the_engine_does(gui):
    import engine.competition as comp
    code = comp.generate_join_code()
    assert gui.normalize_code(f"  {code.lower()} ") == code
    assert gui.normalize_code("") == ""
    assert gui.normalize_code(None) == ""
    # A pasted code with a line break inside it still means the same code.
    assert gui.normalize_code(code[:2] + "\n" + code[2:]) == code


def test_join_delegates_to_the_installed_agent(gui, fake_join):
    fake = fake_join()
    ok, lines = gui.do_join("AB23", config_path="C:\\cfg.json")
    assert ok
    assert fake.calls == [("C:\\cfg.json", "AB23", True)]
    assert "Ada" in "".join(lines)
    # The 3-5 minute Windows first-score latency is documented in
    # RANKED_COMPETITION.md; the window has to say it or players re-join.
    assert "3-5 minutes" in "".join(lines)


def test_a_rejected_code_is_reported_not_raised(gui, fake_join):
    fake = fake_join(error="join rejected (403): invalid join code")
    ok, lines = gui.do_join("NOPE")
    assert not ok
    assert "invalid join code" in "".join(lines)


def test_the_repair_reuses_the_join_module_start(gui, fake_join):
    fake = fake_join()
    ok, text = gui.start_agent_task()
    assert ok
    ok, text = gui.start_agent_task()
    assert ok
    fake.start_error = "could not start Windows agent task (1): Access is denied"
    ok, text = gui.start_agent_task()
    assert not ok and "Access is denied" in text


def test_box_state_never_raises_on_a_box_it_cannot_read(gui, tmp_path):
    state = gui.box_state(str(tmp_path / "absent.json"))
    assert state["error"] and state["ranked"] is None
    assert state["joined"] is None


def test_box_state_reports_a_bound_ranked_box(gui, tmp_path, monkeypatch):
    config = tmp_path / "agent_config.json"
    identity = tmp_path / "identity.json"
    config.write_text(json.dumps({
        "mode": "ranked",
        "manifest_path": str(tmp_path / "manifest.signed.json"),
        "identity_path": str(identity),
        "report_path": str(tmp_path / "report.html"),
        "checkin_interval_s": 60,
        "authoring_public_key_path": None,
        "allow_unsigned_manifest": True,
    }))
    state = gui.box_state(str(config))
    assert state["ranked"] is True and state["joined"] is False
    (tmp_path / "identity.json.enrolled").write_text("enrolled\n")
    assert gui.box_state(str(config))["joined"] is True


def test_first_click_raises_uac_instead_of_failing_quietly(gui, monkeypatch):
    """A filtered token cannot read the sealed install dir at all, so the
    window's first job is to get an elevated instance running."""
    seen = []
    monkeypatch.setattr(gui, "is_windows", lambda: True)
    monkeypatch.setattr(gui, "is_admin", lambda: False)
    monkeypatch.setattr(gui, "notify", lambda *a, **kw: seen.append(a))
    monkeypatch.setattr(gui, "relaunch_elevated", lambda *a, **kw: True)
    monkeypatch.setattr(gui, "run_gui", lambda *a, **kw: seen.append(("gui",)))
    assert gui.main([]) == 0
    assert not any(x == ("gui",) for x in seen)  # this instance exits quietly
    assert "administrator" in seen[0][1].lower()


def test_declined_consent_still_offers_the_form(gui, monkeypatch):
    opened = []
    monkeypatch.setattr(gui, "is_windows", lambda: True)
    monkeypatch.setattr(gui, "is_admin", lambda: False)
    monkeypatch.setattr(gui, "notify", lambda *a, **kw: None)
    monkeypatch.setattr(gui, "relaunch_elevated", lambda *a, **kw: False)
    monkeypatch.setattr(gui, "run_gui", lambda *a, **kw: opened.append(a) or 0)
    gui.main([])
    assert opened == [("",)]  # it tried anyway; the box's error beats our guess


def test_elevated_instance_goes_straight_to_the_form(gui, monkeypatch):
    opened = []
    monkeypatch.setattr(gui, "is_windows", lambda: True)
    monkeypatch.setattr(gui, "is_admin", lambda: False)   # would loop, if not
    monkeypatch.setattr(gui, "run_gui", lambda *a, **kw: opened.append(a) or 0)
    assert gui.main(["--elevated"]) == 0
    assert opened == [("",)]


def test_a_box_with_no_window_support_hands_over_the_terminal_command(
        gui, monkeypatch):
    def no_tkinter(prefill=""):
        raise ImportError("No module named 'tkinter'")
    boxes = []
    monkeypatch.setattr(gui, "is_windows", lambda: False)
    monkeypatch.setattr(gui, "run_gui", no_tkinter)
    monkeypatch.setattr(gui, "notify", lambda *a, **kw: boxes.append(a))
    assert gui.main([]) == 1
    assert gui.TERMINAL_FALLBACK in boxes[0][1]


def test_the_terminal_fallback_is_the_command_that_actually_runs(gui):
    # `huitz` does not exist on a Windows box (packaging/README.md): the
    # fallback must spell out the zipapp path, or it sends players back to the
    # error this whole launcher exists to avoid.
    assert "huitz " not in gui.TERMINAL_FALLBACK
    assert "agent.pyz" in gui.TERMINAL_FALLBACK and "join" in gui.TERMINAL_FALLBACK


def test_elevation_check_is_a_no_op_off_windows(gui, monkeypatch):
    monkeypatch.setattr(gui, "_shell32", lambda: None)
    assert gui.is_admin() is True
    assert gui.relaunch_elevated() is False


def test_relaunch_quotes_the_script_and_tags_the_child(gui, monkeypatch):
    calls = []

    class _Shell:
        def ShellExecuteW(self, *a):
            calls.append(a)
            return 42  # an HINSTANCE: anything > 32 means "started"

    monkeypatch.setattr(gui, "_shell32", lambda: _Shell())
    monkeypatch.setattr(gui, "sys", types.SimpleNamespace(
        executable=r"C:\Python312\pythonw.exe",
        argv=[r"C:\Users\Public\Documents\huitzilopochtli\huitz join-win.pyw"]))
    assert gui.relaunch_elevated() is True
    verb, exe, params = calls[0][1], calls[0][2], calls[0][3]
    assert verb == "runas" and exe == r"C:\Python312\pythonw.exe"
    assert params.endswith("--elevated")
    # The space in the path must survive quoting: it is what the elevated
    # child actually runs.
    assert params.startswith(r'"C:\Users\Public\Documents\huitzilopochtli'
                             r'\huitz join-win.pyw"')


class _FakeTk:
    """A recording stand-in for tkinter.

    There is no display under test, so `run_gui`'s widget code -- the part the
    player actually touches -- would otherwise never execute. Every widget is
    a no-op that remembers the kwargs it was built with, so a test can pull a
    callback back out and invoke it.
    """

    def __init__(self, log):
        self.log = log

    class _Widget:
        def __init__(self, kind, log, **kw):
            self.kind, self.log, self.kw = kind, log, kw
            log.append((kind, kw))

        def pack(self, *a, **kw):
            return self

        def configure(self, **kw):
            self.kw.update(kw)

        def bind(self, seq, fn, *a):
            self.log.append(("bind", (self.kind, seq, fn)))
            return seq

        def focus_set(self):
            return None

        def lift(self):
            return None

        def focus_force(self):
            return None

        def title(self, *_a):
            return None

        def resizable(self, *_a):
            return None

        def after(self, _ms, fn=None, *a):
            if fn:
                fn(*a)
            return None

        def mainloop(self):
            self.log.append(("mainloop", {}))

    class _Var:
        def __init__(self, value=""):
            self.value = value

        def get(self):
            return self.value

    def _font(self, _name):
        class _F:
            def copy(inner):
                return inner

            def configure(inner, **kw):
                return inner
        return _F()

    def module(self):
        log, outer = self.log, self
        mod = types.ModuleType("tkinter")
        for kind in ("Tk", "Frame", "Label", "Entry", "Button"):
            # *_args swallows the parent widget real tkinter takes positionally.
            def make(*_args, _kind=kind, **kw):
                return outer._Widget(_kind, log, **kw)
            setattr(mod, kind, make)
        mod.StringVar = lambda value="": outer._Var(value)
        font_mod = types.ModuleType("tkinter.font")
        font_mod.nametofont = outer._font
        mod.font = font_mod
        return mod


def _wire_form(gui, monkeypatch, state, joined=None):
    """Put the launcher behind the fake tkinter and keep its thread inline."""
    log = []
    fake = _FakeTk(log).module()
    monkeypatch.setattr(gui, "box_state", lambda *a, **kw: state)
    monkeypatch.setitem(sys.modules, "tkinter", fake)
    monkeypatch.setitem(sys.modules, "tkinter.font", fake.font)
    calls = []
    monkeypatch.setattr(gui, "threading", types.SimpleNamespace(
        Thread=lambda target=None, daemon=None: types.SimpleNamespace(
            start=lambda: target())))
    monkeypatch.setattr(gui, "do_join",
                        lambda code, *a, **kw: calls.append(code) or (True, ["joined."]))
    monkeypatch.setattr(gui, "start_agent_task",
                        lambda *a, **kw: calls.append("start") or (True, ["running."]))
    return log, calls


def test_the_form_wires_the_button_to_the_real_join(gui, monkeypatch):
    log, joins = _wire_form(gui, monkeypatch, {
        "scenario": "gavelport-courthouse", "ranked": True, "joined": False,
        "error": None})
    assert gui.run_gui("ab23 ") == 0
    buttons = [kw for kind, kw in log if kind == "Button"]
    join_button = next(kw for kw in buttons if "Join" in str(kw.get("text")))
    join_button["command"]()
    # Normalized on the way in, and the real do_join is what gets called.
    assert joins == ["AB23"]
    assert any(kw.get("text") == "joined." for kind, kw in log if kind == "Label"), \
        "the result has to land in the window, not on a stream nobody sees"


def test_a_box_the_launcher_cannot_read_says_so_before_any_click(
        gui, monkeypatch):
    log, _joins = _wire_form(gui, monkeypatch, {
        "scenario": None, "ranked": None, "joined": None,
        "error": "[WinError 5] Access is denied"})
    assert gui.run_gui() == 0
    texts = " ".join(str(kw.get("text")) for kind, kw in log if kind == "Label")
    assert "Access is denied" in texts


def test_an_already_joined_box_leads_with_the_repair(gui, monkeypatch):
    log, calls = _wire_form(gui, monkeypatch, {
        "scenario": "gavelport-courthouse", "ranked": True, "joined": True,
        "error": None})
    assert gui.run_gui() == 0
    texts = " ".join(str(kw.get("text")) for kind, kw in log if kind == "Label")
    assert "already joined" in texts
    buttons = [kw for kind, kw in log if kind == "Button"]
    repair = next(kw for kw in buttons if "Start the scoring agent" in str(kw.get("text")))
    repair["command"]()
    assert calls == ["start"]

def test_a_console_parent_still_elevates_windowlessly(gui, monkeypatch):
    """python.exe as the parent (the installer found no pythonw) must not
    leave a console window behind the elevated prompt."""
    import os as real_os
    monkeypatch.setattr(real_os.path, "exists",
                        lambda p: p == r"C:\Python312\pythonw.exe")
    assert gui._windowless_interpreter(r"C:\Python312\python.exe") == \
        r"C:\Python312\pythonw.exe"
    # No sibling: use what we have rather than guessing at a path.
    assert gui._windowless_interpreter(r"C:\odd\python.exe") == r"C:\odd\python.exe"
    assert gui._windowless_interpreter(r"C:\Python312\pythonw.exe") == \
        r"C:\Python312\pythonw.exe"
