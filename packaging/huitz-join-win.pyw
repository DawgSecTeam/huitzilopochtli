"""Huitzilopochtli — Join your Windows box (graphical `huitz join`).

Double-click this, type the one-time code from the competition page, click
**Join**, and the box binds to your player slot and starts checking in. It is
the Windows join path; on Linux the player types `huitz join` in a terminal
because `/usr/local/bin/huitz` is on PATH. A Windows box has no such shim
(packaging/README.md), so `huitz join` in PowerShell or cmd.exe answers "the
term 'huitz' is not recognized" — the whole reason this window exists.

Why it asks for administrator rights: a ranked Windows install seals
`C:\\ProgramData\\huitzilopochtli` to SYSTEM + Administrators (the box's own
key lives in `identity.json` there) and the agent runs as the SYSTEM
scheduled task that joining enables. A normal — UAC-filtered — PowerShell is
not in the elevated Administrators group, so both steps fail with access
denied no matter how the command is spelled. The window therefore relaunches
itself elevated (one consent click) and does the join from that instance.

Layout of this file: everything below is platform glue plus a tkinter form;
the actual join is `agent/join.py`, imported out of the installed
`agent.pyz`, so the terminal path and this one can never drift apart. If
tkinter is missing (a minimal Python install), the same join runs through a
plain message box flow instead of the form — the player always gets a way in.
"""
import os
import sys
import threading
import time

#: Install layout — see packaging/README.md ("Windows").
INSTALL_DIR = os.environ.get("HUITZ_INSTALL_DIR",
                             r"C:\ProgramData\huitzilopochtli")
AGENT_PYZ = os.path.join(INSTALL_DIR, "agent.pyz")
CONFIG_PATH = os.environ.get("HUITZ_CONFIG",
                             os.path.join(INSTALL_DIR, "agent_config.json"))

#: The command an operator can paste into an *elevated* PowerShell when this
#: window cannot be used at all (no tkinter, UAC refused, remote box). There is
#: no `huitz` on a Windows box's PATH, which is exactly why this exists.
TERMINAL_FALLBACK = ('python "C:\\ProgramData\\huitzilopochtli\\agent.pyz" join')

#: What the click-instead path is called, so the wording here, the installer's
#: shortcut, and the competition page all name the same thing.
LAUNCHER_NAME = "huitz-join-win.pyw"
SHORTCUT_NAME = "Join Competition Box"


def is_windows() -> bool:
    """Windows-only behavior (the elevation dance) hangs off this one call."""
    return os.name == "nt"


#: Codes come from engine/competition.py's alphabet: unambiguous upper-case
#: letters and digits, no whitespace and no punctuation.
_WHITESPACE = frozenset(chr(c) for c in range(0x21))  # controls + space


def normalize_code(text: str) -> str:
    """Upper-case, with every kind of whitespace removed.

    Codes are `[A-Z2-9]{_CODE_LEN}` from `engine/competition.py` — letters,
    digits, no whitespace, no punctuation — so dropping whitespace can never
    change a real one, while a copy-paste's trailing newline (or a mid-paste
    line break) would otherwise burn the single-use attempt on a hash of
    nothing. A code that arrives clean passes through untouched, so this is
    strictly kinder than `huitz join`, never different from it.
    """
    return "".join(ch for ch in (text or "") if ch not in _WHITESPACE).upper()


# --- win32 glue ---------------------------------------------------------------

def _shell32():
    """ctypes.windll.shell32, or None off Windows / without ctypes."""
    try:
        import ctypes
        return ctypes.windll.shell32
    except Exception:  # noqa: BLE001 — not a win32 box, or a stripped one
        return None


def is_admin() -> bool:
    """True when this process already holds an elevated token."""
    shell32 = _shell32()
    if shell32 is None:
        return True  # POSIX (tests, headless): nothing to elevate.
    try:
        return bool(shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001 — if the check fails, don't loop
        return True


def _windowless_interpreter(exe: str) -> str:
    """python.exe becomes its sibling pythonw.exe when there is one.

    The installer falls back to the console interpreter if it cannot find
    pythonw; without this, elevating would pop a second console window behind
    the prompt for no reason.
    """
    if exe.lower().endswith("python.exe"):
        quiet = exe[:-len("python.exe")] + "pythonw.exe"
        if os.path.exists(quiet):
            return quiet
    return exe


def relaunch_elevated(args=("--elevated",)) -> bool:
    """Ask Windows to start this script again with administrator rights.

    Returns True when consent was given and the elevated instance was
    started (this one should then exit quietly); False when the player
    declined or the shell refused, which is the caller's cue to try the join
    anyway and show whatever error the box gives back.
    """
    shell32 = _shell32()
    if shell32 is None:
        return False
    script = sys.argv[0] or __file__
    if "/" not in script and "\\" not in script:
        # Launched as a bare name from some other directory. (Not
        # os.path.dirname: this file runs on boxes where the separator is a
        # backslash and on Linux under test, where it is not.)
        script = os.path.abspath(script)
    params = " ".join([f'"{script}"', *[str(a) for a in args]])
    exe = _windowless_interpreter(sys.executable or "pythonw.exe")
    try:
        # ShellExecuteW returns an HINSTANCE (>32) on success, <=32 on failure.
        return int(shell32.ShellExecuteW(None, "runas", exe,
                                         params, None, 1)) > 32
    except Exception:  # noqa: BLE001
        return False


def notify(title: str, text: str, kind: str = "info") -> None:
    """Show `text` in a Windows message box (stderr when there is no GUI)."""
    flag = {"info": 0x40, "warn": 0x30, "error": 0x10}.get(kind, 0x40)
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(None, str(text), str(title), flag)
    except Exception:  # noqa: BLE001 — no win32, no desktop
        sys.stderr.write(f"{title}: {text}\n")


# --- box state (everything read from the installed agent) --------------------

def _load_agent():
    """(join, config, main) from the installed zipapp.

    The `.pyz` is a plain zip with `agent/` + `common/` at its root, so
    putting it on sys.path is enough — no duplicated signing or join logic,
    and no second implementation of the bind to keep honest. Raises if the
    box has no usable agent (a broken or half-installed template).
    """
    if AGENT_PYZ not in sys.path:
        sys.path.insert(0, AGENT_PYZ)
    import agent.config
    import agent.join as join_mod
    import agent.__main__ as agent_main
    return join_mod, agent.config, agent_main


def box_state(config_path: str = CONFIG_PATH) -> dict:
    """What this box is, for the window header, without ever raising.

    A failure to read the config is normal here (un-elevated = access
    denied, honor box, half-installed template) and must not stop the joiner:
    the player still gets the code prompt, and the real error surfaces when
    the join itself runs.
    """
    state = {"scenario": None, "ranked": None, "joined": None, "error": None}
    try:
        _join_mod, config_mod, agent_main = _load_agent()
    except Exception as exc:  # noqa: BLE001 — see the docstring
        state["error"] = f"cannot load the installed agent ({exc})"
        return state
    try:
        config = config_mod.load_config(config_path)
    except Exception as exc:  # noqa: BLE001 — see the docstring
        state["error"] = str(exc)
        return state
    state["ranked"] = config.mode.value == "ranked"
    try:
        manifest = agent_main._load_manifest(
            config.manifest_path, config.authoring_public_key_path,
            allow_unsigned=config.allow_unsigned_manifest)
        state["scenario"] = getattr(manifest, "scenario_name", None)
    except Exception:  # noqa: BLE001 — the name is decoration
        pass
    if config.identity_path:
        marker = config.identity_path + ".enrolled"
        state["joined"] = (os.path.isfile(marker)
                           or os.path.isfile(config.identity_path))
    return state


# --- the two actions ---------------------------------------------------------

def do_join(code: str, config_path: str = CONFIG_PATH) -> tuple:
    """Bind + start via agent/join.py. Returns (ok, lines_to_show)."""
    try:
        join_mod, _config, _main = _load_agent()
    except Exception as exc:  # noqa: BLE001
        return False, [f"this box's scoring agent is not usable: {exc}",
                       f"Or join from an elevated terminal:\n  {TERMINAL_FALLBACK}"]
    try:
        result = join_mod.join(config_path, code)
    except join_mod.JoinError as exc:
        return False, [str(exc),
                       "Check the code (it is single-use and expires) and the "
                       "competition page. If the box is already bound, use "
                       "\u25b8 Start the scoring agent."]
    lines = [f"Joined as {result.get('player_name', 'you')} \u00b7 "
             f"{result.get('competition_name', 'your competition')}."]
    ends = result.get("run_ends_at")
    if ends:
        lines.append(f"Your clock stops at "
                     f"{time.strftime('%H:%M UTC', time.gmtime(ends))} "
                     f"(hard stop "
                     f"{time.strftime('%H:%M UTC', time.gmtime(ends - 300))}).")
    lines.append("The scoring agent is starting. On a Windows box the first "
                 "score can take 3-5 minutes to appear \u2014 that delay is "
                 "normal, not a broken join.")
    return True, lines


def start_agent_task() -> tuple:
    """Enable + run the agent: the repair for a bound box whose agent never
    started. `agent/join.py` treats a failed start as a failed join, and a
    consumed code cannot be replayed, so this path has to exist on its own.
    Same single source of truth as the join — on Windows that is
    `schtasks /Change /ENABLE` + `/Run` on the SYSTEM task, so it needs the
    elevated token exactly like joining does."""
    try:
        join_mod, _config, _main = _load_agent()
    except Exception as exc:  # noqa: BLE001
        return False, f"this box's scoring agent is not usable: {exc}"
    try:
        join_mod._start_agent()
    except join_mod.JoinError as exc:
        return False, str(exc)
    return True, ("The scoring agent is enabled and running. On a Windows box "
                  "the first score can take 3-5 minutes to appear.")


# --- the window --------------------------------------------------------------

def run_gui(prefill: str = "") -> int:
    """The code prompt. Returns the process exit code."""
    import tkinter as tk
    from tkinter import font as tkfont

    state = box_state()
    win = tk.Tk()
    win.title("Join your competition box")
    win.resizable(False, False)
    accent = "#2f6f8f"
    ok_color, bad_color = "#1c6b3c", "#7a1f1f"
    head = tkfont.nametofont("TkHeadingFont").copy()
    head.configure(size=13, weight="bold")
    body = tkfont.nametofont("TkTextFont").copy()
    body.configure(size=11)

    frame = tk.Frame(win, padx=18, pady=16)
    frame.pack(fill="both", expand=True)

    title = "Huitzilopochtli \u2014 ranked competition box"
    if state.get("scenario"):
        title = f"Join {state['scenario']}"
    tk.Label(frame, text=title, font=head, anchor="w",
             foreground=accent).pack(fill="x")
    tk.Label(frame, justify="left", wraplength=430, font=body, anchor="w",
             text=("Type the one-time join code from your competition page.\n"
                   "That binds this box to your slot and starts scoring."),
             ).pack(fill="x", pady=(6, 12))

    row = tk.Frame(frame)
    row.pack(fill="x")
    tk.Label(row, text="Join code", font=body).pack(side="left")
    var = tk.StringVar(value=prefill)
    entry = tk.Entry(row, textvariable=var, font=body, width=14,
                     justify="center")
    entry.pack(side="left", padx=(10, 6))
    tk.Label(row, text="exactly as shown on your page", font=body,
             fg="#666").pack(side="left")

    status = tk.Label(frame, justify="left", wraplength=430, anchor="w",
                      font=body, fg=bad_color, text="")
    status.pack(fill="x", pady=(12, 4))

    if state.get("joined"):
        status.configure(fg=ok_color, text=(
            "This box is already joined. If it is not scoring, use "
            "\u25b8 Start the scoring agent."))
    elif state.get("error"):
        # Usually this file running without administrator rights: the join
        # would fail the same way, so say it now rather than after a click.
        status.configure(text=(
            f"Cannot read this box's agent files ({state['error']}). "
            "If Windows asks for administrator rights and you decline, "
            "the join cannot run."))
    buttons = tk.Frame(frame)
    buttons.pack(fill="x", pady=(6, 0))

    # One in-flight action at a time: the join code is single-use, so a second
    # submit racing the first (double Enter) would burn it and show the player
    # an "invalid code" error for their own mistake.
    busy = {"on": False}

    def set_status(text, color=bad_color):
        status.configure(text=text, fg=color)

    def worker(fn, *args):
        busy["on"] = True
        join_btn.configure(state="disabled")
        repair_btn.configure(state="disabled")
        set_status("Contacting the engine\u2026", accent)
        result = {}

        def run():
            try:
                result["value"] = fn(*args)
            except Exception as exc:  # noqa: BLE001 — never die silently
                result["value"] = (False, [f"unexpected error: {exc}"])
            win.after(0, done)

        def done():
            ok, lines = result["value"]
            busy["on"] = False
            join_btn.configure(state="normal")
            repair_btn.configure(state="normal")
            if isinstance(lines, str):
                lines = [lines]
            set_status("\n".join(lines), ok_color if ok else bad_color)
            if ok:
                entry.configure(state="disabled")

        threading.Thread(target=run, daemon=True).start()

    def on_join(_event=None):
        if busy["on"]:
            return "break"
        # Cleaned here so a pasted code's stray newline cannot burn the
        # single-use attempt; `agent/join.py` trims and uppercases on its way
        # to the engine, so both paths send the same four characters.
        code = normalize_code(var.get())
        if not code:
            set_status("Enter the code from your competition page first.")
            entry.focus_set()
            return
        worker(do_join, code)
        return "break"

    def on_repair(_event=None):
        if busy["on"]:
            return "break"
        worker(start_agent_task)
        return "break"

    join_btn = tk.Button(buttons, text="\u25b8 Join", command=on_join,
                         font=body, width=12)
    join_btn.pack(side="left")
    repair_btn = tk.Button(buttons, text="\u25b8 Start the scoring agent",
                           command=on_repair, font=body)
    repair_btn.pack(side="left", padx=(8, 0))
    # Enter is owned by the entry, not the toplevel: a Toplevel <Return>
    # binding also activates the default button, and that would fire the join
    # twice.
    entry.bind("<Return>", on_join)
    join_btn.bind("<Return>", on_join)
    win.after(0, lambda: (win.lift(), win.focus_force(), entry.focus_set()))
    win.mainloop()
    return 0


# --- entry point -------------------------------------------------------------

def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    already_elevated = "--elevated" in argv
    prefill = ""
    if "--code" in argv:
        prefill = argv[argv.index("--code") + 1] if (
            argv.index("--code") + 1 < len(argv)) else ""
    if is_windows() and not already_elevated and not is_admin():
        notify("Join your competition box",
               "Joining needs administrator rights: the code, the box's own "
               "key and the scoring agent all live in a protected folder.\n\n"
               "Click Yes on the Windows prompt, then enter your code in the "
               "window that opens.", "info")
        if relaunch_elevated():
            return 0
        notify("Administrator rights declined",
               "Windows did not grant administrator rights, so joining from "
               "here may fail.\n\nTo join instead, open Windows PowerShell "
               "as administrator and run:\n  " + TERMINAL_FALLBACK, "warn")
        # Fall through: on a box whose ACLs are looser the join still works,
        # and the real error is more useful than our guess about UAC.
    try:
        return run_gui(prefill)
    except ImportError as exc:
        # tkinter is part of the python.org install; a stripped Python (or the
        # Store build with it turned off) still gets a working joiner.
        notify("Join your competition box",
               f"This box's Python has no window support ({exc}).\n\nOpen "
               "Windows PowerShell as administrator and run:\n  "
               + TERMINAL_FALLBACK + "\n\nthen type your one-time code when "
               "it asks.", "warn")
        return 1
    except Exception as exc:  # noqa: BLE001 — a click must never vanish
        notify("Join your competition box",
               f"The join window could not open: {exc}\n\nUse the terminal "
               "instead (elevated PowerShell):\n  " + TERMINAL_FALLBACK, "error")
        return 1


if __name__ == "__main__":
    sys.exit(main())
