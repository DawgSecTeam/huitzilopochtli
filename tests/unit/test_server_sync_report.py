"""Sweep-loop sync error reporting: loud on change, quiet when steady.

A failed box/pool scan fails safe -- the store mirror keeps serving the last
good pass -- so the sweep loop is the only place an operator would ever hear
about an unreadable pools file. It must report the first sight of an error,
not spam every 15 s with the same one, and announce recovery.
"""
from engine.server import _sync_report


def test_quiet_stays_quiet():
    assert _sync_report([], None) == (None, None)


def test_first_sight_of_an_error_is_reported():
    message, text = _sync_report(["/etc/huitzilopochtli/pools.yaml: boom"], None)
    assert message == "/etc/huitzilopochtli/pools.yaml: boom"
    assert text == message


def test_repeated_identical_errors_log_once():
    _message, text = _sync_report(["boom"], None)
    message, again = _sync_report(["boom"], text)
    assert message is None
    assert again == text


def test_a_changed_error_is_reported_again():
    _message, text = _sync_report(["boom"], None)
    message, text2 = _sync_report(["boom", "and worse"], text)
    assert message == "boom; and worse"
    assert text2 == message


def test_recovery_is_announced_once():
    _message, text = _sync_report(["boom"], None)
    message, text2 = _sync_report([], text)
    assert message == "recovered"
    assert text2 == ""
    message3, text3 = _sync_report([], text2)
    assert message3 is None and text3 == ""
