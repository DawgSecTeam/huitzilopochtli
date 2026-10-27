"""One decision, one place: is this target Windows or POSIX?

Two different strings describe a box's platform and they are not the same
vocabulary:

- the *declared* OS from a nakon machine (``debian-13-cli``, ``ubuntu-xfce``,
  ``windows-server``), authored in ``boxes/<box>/nakon.json``;
- the *observed* OS a provider handle reports after connecting
  (``boxbuilder.providers.ssh.SshHandle.os_name``), normalized to
  ``"windows"`` or ``"posix"``.

Everything that branches on platform (install layout, config separator, theme
seed family, verify/seal behaviour) calls :func:`family` so the two
vocabularies can never drift apart. Adding a new declared OS means adding it
to ``KNOWN_OS``; the normalization rule elsewhere is a case-insensitive
substring match on ``win``, which keeps unknown-but-obviously-Windows values
behaving correctly.
"""
import re

WINDOWS = "windows"
POSIX = "posix"

# Declared OS values the bundled seeds and install layout have been exercised
# against. Validation rejects anything else so a typo cannot silently choose
# the POSIX layout on a Windows guest.
KNOWN_OS = {
    "debian-13-cli": POSIX,
    "ubuntu-xfce": POSIX,
    "linux": POSIX,
    "windows-server": WINDOWS,
    "windows": WINDOWS,
}


def family(os_name) -> str:
    """Platform family for a declared or detected OS string."""
    if not isinstance(os_name, str) or not os_name.strip():
        return POSIX
    normalized = os_name.strip().lower()
    if normalized in KNOWN_OS:
        return KNOWN_OS[normalized]
    if re.search(r"(^|[^a-z])win", normalized):
        return WINDOWS
    return POSIX


def is_windows(os_name) -> bool:
    return family(os_name) == WINDOWS


def is_posix(os_name) -> bool:
    return family(os_name) == POSIX


def known_os(os_name) -> bool:
    return isinstance(os_name, str) and os_name.strip().lower() in KNOWN_OS
