"""Terminal kit for the huitz CLI (agent/cli.py) — stdlib only, portable.

Everything visual the CLI does goes through here so the command modules stay
pure text layout. Behavior contract:

- **Color depth** is detected once (`Style.detect`): NO_COLOR / non-TTY /
  TERM=dumb degrade to plain text; COLORTERM=truecolor, TERM=*256color*, and
  plain 16-color terminals each get a faithful accent (theme hex -> nearest
  palette entry). `override` lets `--color=always|never|auto` win.
- **Unicode** (box characters, check marks) is used only when the output
  stream is UTF-8; otherwise ASCII equivalents. Same rule git/ls use.
- **No curses** — the zipapp must also run on Windows (pinecrest boxes),
  where curses does not exist. Frames are plain ANSI; key polling is
  termios+select on POSIX and msvcrt on Windows.
"""
import os
import re
import shutil
import sys

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def visible_len(text: str) -> int:
    """Display width of possibly-styled text (SGR sequences count 0)."""
    return len(_ANSI_RE.sub("", text))


def truncate_ansi(text: str, width: int) -> str:
    """Clip `text` to `width` visible columns without splitting escape
    sequences; appends a reset only when styling was actually cut mid-run
    (plain text must stay plain — a stray reset is noise on dumb terminals)."""
    if visible_len(text) <= width:
        return text
    out = []
    used = 0
    saw_sgr = False
    i = 0
    while i < len(text) and used < width:
        m = _ANSI_RE.match(text, i)
        if m:
            out.append(m.group(0))
            saw_sgr = True
            i = m.end()
            continue
        out.append(text[i])
        used += 1
        i += 1
    if saw_sgr:
        out.append("\x1b[0m")
    return "".join(out)

# --- color depths ------------------------------------------------------------

NONE, C16, C256, TRUECOLOR = 0, 4, 8, 24

# Semantic palette — the same hex values agent/report_page.py uses for the
# HTML report (ok/bad/warn/muted), so terminal and web agree on meaning.
SEMANTIC = {
    "ok": "#1a7f37",
    "bad": "#cf222e",
    "warn": "#9a6700",
    "muted": "#6e7378",
    "ink": None,       # terminal default
}

_C16_RGB = [
    (0, 0, 0), (205, 0, 0), (0, 205, 0), (205, 205, 0),
    (0, 0, 238), (205, 0, 205), (0, 205, 205), (229, 229, 229),
    (127, 127, 127), (255, 0, 0), (0, 255, 0), (255, 255, 0),
    (92, 92, 255), (255, 0, 255), (0, 255, 255), (255, 255, 255),
]


def _cube_gray(i: int) -> tuple:
    v = 8 + 10 * (i - 232)
    return (v, v, v)


def _palette_rgb(i: int) -> tuple:
    """xterm-256 palette entry i as (r, g, b)."""
    if i < 16:
        return _C16_RGB[i]
    if i < 232:
        i -= 16
        levels = (0, 95, 135, 175, 215, 255)
        return (levels[i // 36], levels[(i // 6) % 6], levels[i % 6])
    return _cube_gray(i)


def _hex_rgb(value: str) -> tuple | None:
    value = value.strip()
    if not value.startswith("#") or len(value) != 7:
        return None
    try:
        return (int(value[1:3], 16), int(value[3:5], 16), int(value[5:7], 16))
    except ValueError:
        return None


def _nearest(rgb: tuple, count: int) -> int:
    best, best_d = 0, None
    for i in range(count):
        pr = _palette_rgb(i)
        d = sum((a - b) ** 2 for a, b in zip(rgb, pr))
        if best_d is None or d < best_d:
            best, best_d = i, d
    return best


def _rgb_ansi(rgb: tuple, depth: int) -> str | None:
    """SGR foreground parameter for an RGB at the given depth."""
    if depth == TRUECOLOR:
        return f"38;2;{rgb[0]};{rgb[1]};{rgb[2]}"
    if depth == C256:
        return f"38;5;{_nearest(rgb, 256)}"
    if depth == C16:
        return f"38;5;{_nearest(rgb, 16)}"
    return None


# --- detection ---------------------------------------------------------------

def _stream_utf8(stream) -> bool:
    enc = getattr(stream, "encoding", "") or ""
    return "utf" in enc.lower().replace("-", "")


def detect_depth(stream, override: str = "auto") -> int:
    """Color depth for `stream`: one of NONE/C16/C256/TRUECOLOR.

    override: "auto" (environment decides), "always" (force best depth),
    "never" (plain text). NO_COLOR (https://no-color.org) and TERM=dumb win
    over auto; FORCE_COLOR forces color back on for piped runs that want it.
    """
    override = (override or "auto").lower()
    if override == "never":
        return NONE
    if os.environ.get("NO_COLOR"):
        if override != "always" and not os.environ.get("FORCE_COLOR"):
            return NONE
    term = os.environ.get("TERM", "")
    if term == "dumb" and override != "always":
        return NONE
    if override == "always" or os.environ.get("FORCE_COLOR") or stream.isatty():
        colorterm = os.environ.get("COLORTERM", "").lower()
        if "truecolor" in colorterm or "24bit" in colorterm:
            return TRUECOLOR
        if "256color" in term or os.name == "nt" or colorterm:
            return C256
        return C16
    return NONE


def detect_width(stream) -> int:
    """Current terminal width, >= 20 (below that, layout is hopeless)."""
    try:
        cols = shutil.get_terminal_size(fallback=(80, 24)).columns
    except Exception:  # noqa: BLE001 — any oddity falls back to 80
        cols = 80
    del stream
    return max(20, cols)


def is_interactive(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty()


# --- windows VT --------------------------------------------------------------

def enable_windows_vt() -> bool:
    """Best-effort ENABLE_VIRTUAL_TERMINAL_PROCESSING on Windows consoles.
    Returns True when nothing needed doing (POSIX) or the mode was set."""
    if os.name != "nt":
        return True
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(
            handle, mode.value | 0x0004))  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:  # noqa: BLE001 — best effort; plain output still works
        return False


# --- styling -----------------------------------------------------------------

class Style:
    """ANSI styling at the detected depth; a no-op at NONE.

    color() accepts semantic names (ok/bad/warn/muted/ink), theme accents
    as "#rrggbb", or raw SGR attribute ints (1 = bold). Text is escaped at
    call time; layout helpers pad plain strings BEFORE styling so widths
    never need ANSI-aware math.
    """

    def __init__(self, depth: int, utf8: bool = True, accent: str | None = None):
        self.depth = depth
        self.utf8 = utf8
        self.accent = accent

    @classmethod
    def detect(cls, stream, override: str = "auto", accent: str | None = None) -> "Style":
        return cls(detect_depth(stream, override), _stream_utf8(stream), accent)

    def _sgr_params(self, *specs) -> list:
        params = []
        for spec in specs:
            if isinstance(spec, int):
                params.append(str(spec))
                continue
            rgb = None
            if spec == "accent":
                spec = self.accent
            if spec and spec.startswith("#"):
                rgb = _hex_rgb(spec)
            elif spec in SEMANTIC:
                named = SEMANTIC[spec]
                rgb = _hex_rgb(named) if named else None
            if rgb is not None:
                param = _rgb_ansi(rgb, self.depth)
                if param:
                    params.append(param)
            elif spec:
                params.append(str(spec))
        return params

    def color(self, text: str, *specs) -> str:
        params = self._sgr_params(*specs)
        if not params or self.depth == NONE:
            return text
        return f"\x1b[{';'.join(params)}m{text}\x1b[0m"

    def bold(self, text: str) -> str:
        return self.color(text, 1)

    def dim(self, text: str) -> str:
        return self.color(text, 2)

    def reverse(self, text: str) -> str:
        return self.color(text, 7)


# --- symbols & layout --------------------------------------------------------

class Symbols:
    """Unicode when the stream can take it, ASCII otherwise."""

    def __init__(self, utf8: bool):
        self.utf8 = utf8

    @property
    def check(self):
        return "✓" if self.utf8 else "+"

    @property
    def cross(self):
        return "✗" if self.utf8 else "x"

    @property
    def bullet(self):
        return "•" if self.utf8 else "*"

    @property
    def up(self):
        return "▲" if self.utf8 else "^"

    @property
    def down(self):
        return "▼" if self.utf8 else "v"

    @property
    def block(self):
        return "█" if self.utf8 else "#"

    @property
    def light(self):
        return "░" if self.utf8 else "-"

    @property
    def hline(self):
        return "─" if self.utf8 else "-"

    @property
    def ellipsis(self):
        return "…" if self.utf8 else "~"

    @property
    def bell(self):
        # Terminal bell: the CLI's native analog of the box's score-change
        # chime, audible over SSH where the desktop PulseAudio is not.
        return "\a"


def ellipsize(text: str, width: int, symbols: Symbols) -> str:
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width == 1:
        return ""
    return text[: width - 1] + symbols.ellipsis


def pad(text: str, width: int) -> str:
    if len(text) >= width:
        return text[:width]
    return text + " " * (width - len(text))


def rule(width: int, symbols: Symbols) -> str:
    return symbols.hline * max(0, width)


def progress_bar(pct: int, width: int, symbols: Symbols) -> str:
    """`width` includes the two bracket characters."""
    inner = max(3, width - 2)
    filled = int(round(inner * max(0, min(100, pct)) / 100.0))
    return "[" + symbols.block * filled + symbols.light * (inner - filled) + "]"


def fmt_mmss(seconds: float) -> str:
    secs = max(0, int(seconds))
    m, s = divmod(secs, 60)
    if m >= 60:
        h, m = divmod(m, 60)
        return f"{h}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"


# --- frame control & key polling (watch mode) --------------------------------

ALT_ENTER = "\x1b[?1049h"
ALT_EXIT = "\x1b[?1049l"
HIDE_CURSOR = "\x1b[?25l"
SHOW_CURSOR = "\x1b[?25h"
HOME_CLEAR = "\x1b[H\x1b[2J"


class KeyPoller:
    """Single-key input for the watch loop. `poll(timeout_s)` returns the
    key name ("q", " ", "ctrl-c") or "" on timeout. Non-interactive stdin
    is supported (poll always times out) so `watch --once` logic can share
    the code path."""

    def __init__(self, stream=None):
        self.stream = stream or sys.stdin
        self._fd = None
        self._saved = None
        if os.name == "nt":
            try:
                import msvcrt
                self._msvcrt = msvcrt
            except ImportError:
                self._msvcrt = None
            return
        if self.stream is not None and hasattr(self.stream, "fileno"):
            import select
            import termios
            import tty
            self._select = select
            try:
                self._fd = self.stream.fileno()
                self._saved = termios.tcgetattr(self._fd)
                tty.setcbreak(self._fd)
                self._termios = termios
            except (termios.error, ValueError, OSError):
                self._fd = None
                self._saved = None

    def poll(self, timeout_s: float) -> str:
        if os.name == "nt" and getattr(self, "_msvcrt", None):
            import time
            deadline = time.monotonic() + timeout_s
            while time.monotonic() < deadline:
                if self._msvcrt.kbhit():
                    ch = self._msvcrt.getwch()
                    if ch in ("\x00", "\xe0"):
                        self._msvcrt.getwch()  # swallow function-key prefix
                        continue
                    if ch == "\x03":
                        return "ctrl-c"
                    return ch
                time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
            return ""
        if self._fd is None:
            import time
            time.sleep(max(0.0, timeout_s))
            return ""
        ready, _, _ = self._select.select([self._fd], [], [], timeout_s)
        if not ready:
            return ""
        ch = os.read(self._fd, 1).decode("utf-8", "replace")
        if ch == "\x03":
            return "ctrl-c"
        return ch

    def close(self):
        if self._fd is not None and self._saved is not None:
            try:
                self._termios.tcsetattr(self._fd, self._termios.TCSADRAIN,
                                        self._saved)
            except Exception:  # noqa: BLE001 — restoring is best-effort
                pass
            self._fd = None
