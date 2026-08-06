"""pytest fixtures for boxbuilder integration tests.

The fake provider/handle classes + install_fake_nakon helper live in _fakes.py
(so tests can import them by name without conftest-name collision). This file
holds only the pytest fixtures that wrap them.
"""
import pytest

from tests.integration.boxbuilder._fakes import FakeProvider  # noqa: F401  (re-exported)


@pytest.fixture
def fake_provider():
    return FakeProvider()


@pytest.fixture
def fake_provider_factory(fake_provider):
    """A provider_factory matching plant_box's signature: (name, cfg) -> (provider, handle)."""
    def _factory(name, cfg):
        handle = fake_provider.start(cfg)
        return fake_provider, handle
    return _factory
