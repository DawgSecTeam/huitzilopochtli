"""One decision, one place: Windows or POSIX.

Two vocabularies exist — the *declared* OS from a nakon machine and the
*observed* ``os_name`` a handle reports. Everything that branches on
platform calls family(), so the two never drift apart."""
import re

WINDOWS = "windows"
POSIX = "posix"

# Declared OS values the bundled seeds + install layout are exercised
# against; validation rejects anything else, so a typo cannot silently pick
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


def known_os(os_name) -> bool:
    return isinstance(os_name, str) and os_name.strip().lower() in KNOWN_OS
