"""Score-change alerts: sound + desktop notification (CyberPatriot parity).

The scoring engine never calls into this module -- scoring stays a pure
function of (evidence, rubric, clock) (§2.1). After a run produces a new
total, `consume_delta` diffs it against the persisted baseline from the
previous run and `announce` makes noise about the change:

    gain  -> the points-gained chime + a normal-urgency toast
    loss  -> the penalty alarm + a critical-urgency toast

The agent runs as root on a headless-ish box; reaching the *desktop
user's* PulseAudio/session bus means dropping to them with sudo -u plus
their XDG_RUNTIME_DIR, the same real-session pattern as
boxes/shared/fix-xubuntu-vnc-display.sh. Everything here is best-effort
(§9.1): a box with no sound stack or notification daemon still scores
and reports -- announce never raises.

Pure stdlib; agent.sounds carries the embedded WAV bytes so the zipapp
needs no data-file loading.
"""
import json
import os
import subprocess
import sys

import agent.sounds

_STATE_FILENAME = "score_state.json"
# alarm.wav is ~5s; let playback start and finish with headroom.
_PLAY_TIMEOUT_S = 12.0
_NOTIFY_TIMEOUT_S = 5.0


# --- score baseline ---------------------------------------------------------

def state_path_for(report_path: str) -> str:
    """Baseline file lives next to the cached report (same install dir)."""
    return os.path.join(
        os.path.dirname(os.path.abspath(report_path)), _STATE_FILENAME
    )


def _load_state(path: str) -> dict | None:
    """Return {'total': int, 'scenario_version': str} or None if absent/bad."""
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
    if not isinstance(version, str):
        return None
    return {"total": total, "scenario_version": version}


def _write_state(path: str, total: int, scenario_version: str) -> None:
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(
                {"total": total, "scenario_version": scenario_version}, f
            )
        os.rename(tmp, path)
    except OSError as e:
        print(
            f"WARNING: could not persist score state {path!r}: {e}",
            file=sys.stderr,
        )
        try:
            os.remove(tmp)
        except OSError:
            pass


def consume_delta(state_path: str, total: int, scenario_version: str) -> int | None:
    """Diff this run's total against the baseline; persist the new one.

    Returns None when there is no comparable baseline -- first run after
    install or re-arm, a corrupted state file, or a different
    scenario_version (the box was rebuilt). Silence on those is the point:
    a fresh box must not be greeted by the penalty alarm. Otherwise returns
    ``total - previous`` (0 = unchanged).
    """
    state = _load_state(state_path)
    delta = None
    if state is not None and state["scenario_version"] == scenario_version:
        delta = total - state["total"]
    _write_state(state_path, total, scenario_version)
    return delta


# --- desktop session discovery ----------------------------------------------

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
    """Real users with a running systemd user bus -- i.e. a live login whose
    PulseAudio/notifyd we can actually reach. Falls back to the first real
    user when none has one (best effort: sudo -u into a dead session is a
    no-op, but trying costs nothing)."""
    users = _real_users()
    live = [
        (name, uid) for name, uid in users
        if os.path.exists(f"/run/user/{uid}/bus")
    ]
    return live or users[:1]


# --- best-effort sound + toast ----------------------------------------------

def _run(cmd: list, timeout: float) -> bool:
    try:
        subprocess.run(
            cmd, timeout=timeout, check=False,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return True
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
    """Write the embedded WAV to a world-readable temp path for the desktop
    user's player. tmp+rename so concurrent runs never see a partial file."""
    path = f"/tmp/huitz-{kind}.wav"
    tmp = path + ".tmp"
    try:
        with open(tmp, "wb") as f:
            f.write(agent.sounds.wave_bytes(kind))
        os.chmod(tmp, 0o644)
        os.rename(tmp, path)
        return path
    except OSError as e:
        print(f"WARNING: could not extract {kind} sound: {e}", file=sys.stderr)
        return None


def _play_sound(kind: str, user: str | None, uid: int | None) -> None:
    path = _extract_sound(kind)
    if path is None:
        return
    if user is not None:
        # PulseAudio first (session volume/routing), then bare ALSA as the
        # user, then bare ALSA as root -- aplay exists on every Xubuntu
        # image, paplay usually; any single success is enough.
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
        sessions = _live_sessions()
        for user, uid in sessions:
            _play_sound(kind, user, uid)
            _notify(summary, body, urgency, user, uid)
        if not sessions:
            _play_sound(kind, None, None)
    except Exception as e:  # noqa: BLE001 — cosmetics must never stall a run
        print(f"WARNING: score-change notification failed: {e}", file=sys.stderr)
