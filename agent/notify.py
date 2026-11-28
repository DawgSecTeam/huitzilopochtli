"""Score-change alerts: sound + desktop notification. Best-effort (§9.1):
announce never raises — a run never stalls on cosmetics. Scoring never
calls into this module (§2.1). Reaching the desktop user's session bus
means sudo -u with their XDG_RUNTIME_DIR (_as_user); the chime WAVs are
embedded in agent.sounds for the zipapp."""
import json
import os
import subprocess
import sys
import tempfile

import agent.sounds

_IS_WINDOWS = os.name == "nt"

_STATE_FILENAME = "score_state.json"
_PLAY_TIMEOUT_S = 12.0
_NOTIFY_TIMEOUT_S = 5.0

def state_path_for(report_path: str) -> str:
    """Baseline file lives next to the cached report (same install dir)."""
    return os.path.join(
        os.path.dirname(os.path.abspath(report_path)), _STATE_FILENAME
    )

def _load_state(path: str) -> dict | None:
    """Return {'total': int, 'scenario_version': int|str} or None if
    absent/bad. schema says int (§6.4); str tolerated for foreign writers."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    total = data.get("total")
    version = data.get("scenario_version")
    if isinstance(total, bool) or not isinstance(total, int):
        return None
    if isinstance(version, bool) or not isinstance(version, (int, str)):
        return None
    return {"total": total, "scenario_version": version}

def _write_state(path: str, total: int, scenario_version: str) -> None:
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(
                {"total": total, "scenario_version": scenario_version}, f
            )
        os.replace(tmp, path)
    except OSError as e:
        print(
            f"WARNING: could not persist score state {path!r}: {e}",
            file=sys.stderr,
        )
        try:
            os.remove(tmp)
        except OSError:
            pass

def peek_delta(state_path: str, total: int, scenario_version) -> int | None:
    """Return the change versus the baseline WITHOUT persisting the new total.

    Callers peek before publishing and record_score only after — a failed
    write must not consume the notification or advance the baseline."""
    state = _load_state(state_path)
    if state is not None and state["scenario_version"] == scenario_version:
        return total - state["total"]
    return None

def record_score(state_path: str, total: int, scenario_version) -> None:
    _write_state(state_path, total, scenario_version)

def consume_delta(state_path: str, total: int, scenario_version: str) -> int | None:
    """Diff and persist in one step (kept for callers/tests that want it)."""
    delta = peek_delta(state_path, total, scenario_version)
    record_score(state_path, total, scenario_version)
    return delta

def _real_users():
    """All real interactive accounts (same heuristic as sync-report.sh:
    uid 1000-59999 with a login shell). Empty on non-POSIX platforms."""
    try:
        import pwd
    except ImportError:
        return []
    users = []
    for entry in pwd.getpwall():
        if not (1000 <= entry.pw_uid < 60000):
            continue
        shell = entry.pw_shell or ""
        if shell.endswith("/nologin") or shell.endswith("/false"):
            continue
        users.append((entry.pw_name, entry.pw_uid))
    return users

def _live_sessions():
    """Real users with a live systemd user bus (reachable session). Falls
    back to the first real user — trying a dead session costs nothing."""
    users = _real_users()
    live = [
        (name, uid) for name, uid in users
        if os.path.exists(f"/run/user/{uid}/bus")
    ]
    return live or users[:1]

def _run(cmd: list, timeout: float) -> bool:
    try:
        proc = subprocess.run(
            cmd, timeout=timeout, check=False,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False

def _as_user(user: str, uid: int, argv: list) -> list:
    """Run argv inside the user's live session (their runtime dir + session
    bus), so PulseAudio and the notification daemon are reachable."""
    return [
        "sudo", "-u", user, "env",
        f"XDG_RUNTIME_DIR=/run/user/{uid}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus",
        *argv,
    ]

def _extract_sound(kind: str) -> str | None:
    """Write the embedded WAV to a fresh world-readable /tmp file.

    Root + world-writable /tmp: a predictable name lets a local user
    pre-plant a symlink and redirect root's write/chmod. mkstemp is
    random + O_EXCL."""
    try:
        fd, path = tempfile.mkstemp(prefix=f"huitz-{kind}-", suffix=".wav",
                                    dir="/tmp")
    except OSError as e:
        print(f"WARNING: could not extract {kind} sound: {e}", file=sys.stderr)
        return None
    try:
        # mkstemp creates 0600; the player runs as the desktop user.
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "wb") as f:
            f.write(agent.sounds.wave_bytes(kind))
        return path
    except OSError as e:
        print(f"WARNING: could not extract {kind} sound: {e}", file=sys.stderr)
        _unlink_quietly(path)
        return None

def _unlink_quietly(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass

def _play_sound(kind: str, user: str | None, uid: int | None) -> None:
    path = _extract_sound(kind)
    if path is None:
        return
    try:
        _play_file(path, user, uid)
    finally:
        _unlink_quietly(path)

def _play_file(path: str, user: str | None, uid: int | None) -> None:
    if user is not None:
        if _run(_as_user(user, uid, ["paplay", path]), _PLAY_TIMEOUT_S):
            return
        if _run(_as_user(user, uid, ["aplay", "-q", path]), _PLAY_TIMEOUT_S):
            return
    _run(["aplay", "-q", path], _PLAY_TIMEOUT_S)

def _notify(summary: str, body: str, urgency: str,
            user: str, uid: int) -> None:
    """Desktop toast via the session bus. notify-send first (libnotify-bin),
    falling back to a raw org.freedesktop.Notifications.Notify call through
    dbus-send, which exists wherever dbus does."""
    argv = ["notify-send", "-a", "Huitzilopochtli", "-u", urgency, summary, body]
    if _run(_as_user(user, uid, argv), _NOTIFY_TIMEOUT_S):
        return
    dbus_argv = [
        "dbus-send", "--session", "--type=method_call",
        "--dest=org.freedesktop.Notifications",
        "/org/freedesktop/Notifications",
        "org.freedesktop.Notifications.Notify",
        "string:huitzilopochtli", "uint32:0", "string:",
        f"string:{summary}", f"string:{body}",
        "array:string:", "dict:string:variant:", "int32:5000",
    ]
    _run(_as_user(user, uid, dbus_argv), _NOTIFY_TIMEOUT_S)

def _copy(delta: int, total: int, title: str) -> tuple[str, str, str]:
    """(summary, body, urgency) for the notification."""
    title = title or "Scoring engine"
    if delta > 0:
        return (
            f"{title} — points gained",
            f"+{delta} pts. Score is now {total}.",
            "normal",
        )
    return (
        f"{title} — penalty applied",
        f"{delta} pts: a scored setting was undone or a new issue "
        f"introduced. Score is now {total}.",
        "critical",
    )

def announce(delta: int, total: int, title: str = "",
             enabled: bool = True) -> None:
    """Play the score-change sound and raise a desktop toast. Never raises:
    every failure mode (no session, no tools, no daemon) is swallowed with
    at most a WARNING -- a scoring run must never stall on cosmetics."""
    if not enabled or delta == 0:
        return
    try:
        kind = "gain" if delta > 0 else "penalty"
        summary, body, urgency = _copy(delta, total, title)
        if _IS_WINDOWS:
            _announce_windows(kind, summary, body)
            return
        sessions = _live_sessions()
        for user, uid in sessions:
            _play_sound(kind, user, uid)
            _notify(summary, body, urgency, user, uid)
        if not sessions:
            _play_sound(kind, None, None)
    except Exception as e:  # noqa: BLE001 — cosmetics must never stall a run
        print(f"WARNING: score-change notification failed: {e}", file=sys.stderr)

def _announce_windows(kind: str, summary: str, body: str) -> None:
    """Sound via winsound (plays the embedded WAV bytes directly -- no temp
    file, stdlib), then a best-effort toast through the Windows Runtime
    notification API via PowerShell (works unmodified on stock PowerShell
    5.1; fails silently where the toast stack is unavailable)."""
    try:
        import winsound
        winsound.PlaySound(agent.sounds.wave_bytes(kind),
                           winsound.SND_MEMORY | winsound.SND_NODEFAULT)
    except Exception as e:
        print(f"WARNING: windows sound playback failed: {e}", file=sys.stderr)

    try:
        ps = (_WINDOWS_TOAST_TEMPLATE
              .replace("__SUMMARY__", _ps_escape(summary))
              .replace("__BODY__", _ps_escape(body)))
        _run(["powershell.exe", "-NoProfile", "-NonInteractive",
              "-ExecutionPolicy", "Bypass", "-Command", ps], _NOTIFY_TIMEOUT_S)
    except Exception as e:
        print(f"WARNING: windows toast failed: {e}", file=sys.stderr)

def _ps_escape(text: str) -> str:
    """Single-quote escaping for string literals inside PowerShell snippets."""
    return "'" + text.replace("'", "''") + "'"

_WINDOWS_TOAST_TEMPLATE = r"""
$ErrorActionPreference = 'SilentlyContinue'
$null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$texts = $template.GetElementsByTagName('text')
$null = $texts.Item(0).AppendChild($template.CreateTextNode(__SUMMARY__))
$null = $texts.Item(1).AppendChild($template.CreateTextNode(__BODY__))
$toast = [Windows.UI.Notifications.ToastNotification]::new($template)
$appId = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show($toast)
"""
