"""Boxbuilder admin-API transport security (1.0)."""
import pytest

from boxbuilder import engine


def test_plain_http_admin_call_to_non_loopback_is_refused(monkeypatch):
    monkeypatch.delenv("HUITZILOPOCHTLI_ALLOW_INSECURE_ENGINE", raising=False)
    with pytest.raises(engine.EngineError, match="plain HTTP"):
        engine._request("http", "192.168.50.10", 8080, "POST",
                        "/admin/tokens", "secret", body={})


def test_plain_http_loopback_is_allowed(monkeypatch):
    # No network call is made because the connection fails immediately; what
    # matters is that the security guard does not fire for loopback.
    monkeypatch.delenv("HUITZILOPOCHTLI_ALLOW_INSECURE_ENGINE", raising=False)
    with pytest.raises(engine.EngineError, match="could not reach engine"):
        engine._request("http", "127.0.0.1", 1, "POST", "/admin/tokens",
                        "secret", body={}, timeout=0.2)


def test_insecure_opt_in_allows_non_loopback(monkeypatch):
    monkeypatch.setenv("HUITZILOPOCHTLI_ALLOW_INSECURE_ENGINE", "1")
    with pytest.raises(engine.EngineError, match="could not reach engine"):
        engine._request("http", "192.168.50.10", 1, "POST", "/admin/tokens",
                        "secret", body={}, timeout=0.2)
