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


# --- response headers ---------------------------------------------------------


class _FakeConn:
    def __init__(self):
        self.status = None
        self.headers = []
        self.body = b""

    def send_response(self, status):
        self.status = status

    def send_header(self, k, v):
        self.headers.append((k, v))

    def end_headers(self):
        pass

    @property
    def wfile(self):
        return self

    def write(self, b):
        self.body = b


def test_send_html_sets_csp_and_no_store():
    from engine.server import Handler
    f = _FakeConn()
    Handler._send_html(f, 200, "<p>x</p>")
    hd = dict(f.headers)
    csp = hd["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "'unsafe-inline'" not in csp.split("script-src")[1].split(";")[0]
    assert "style-src 'self' 'unsafe-inline'" in csp  # accent vars body attribute
    assert "frame-ancestors 'self'" in csp and "base-uri 'none'" in csp
    assert hd["Cache-Control"] == "no-store"
    assert hd["X-Frame-Options"] == "SAMEORIGIN"


def test_send_static_is_immutable_and_cacheable():
    from engine.server import Handler
    f = _FakeConn()
    Handler._send_static(f, "text/css", "body{}")
    hd = dict(f.headers)
    assert "max-age=31536000, immutable" in hd["Cache-Control"]
    assert hd["Content-Type"].startswith("text/css")
    assert f.body == b"body{}"


def test_send_html_frag_param_returns_only_the_poll_node():
    from engine.server import Handler
    page = ('<html><body><div id="board" data-poll="5000">'
            '<p>Ada <div class="x">nested</div></p></div>'
            '<div id="other">x</div></body></html>')
    f = _FakeConn(); f.path = "/c/demo?frag=board"
    Handler._send_html(f, 200, page)
    assert f.body.decode() == ('<div id="board" data-poll="5000">'
                               '<p>Ada <div class="x">nested</div></p></div>')
    assert "no-store" in dict(f.headers)["Cache-Control"]
    # No frag param -> the full page, untouched.
    f2 = _FakeConn(); f2.path = "/c/demo"
    Handler._send_html(f2, 200, page)
    assert f2.body.decode() == page
    # Unknown frag id -> full-page fallback (the client still finds the node).
    f3 = _FakeConn(); f3.path = "/c/demo?frag=nope"
    Handler._send_html(f3, 200, page)
    assert f3.body.decode() == page
