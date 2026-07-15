"""Shared pytest fixtures for evo-core.

Exposes the self-contained scenario factories (see ``tests/scenarios.py``) as
fixtures for convenience. Tests may also import the factories directly.
"""

from __future__ import annotations

import pytest

from tests.scenarios import mounted_secret_scenario, pivot_scenario, secret_read_scenario


@pytest.fixture
def secret_read():
    return secret_read_scenario()


@pytest.fixture
def mounted_secret():
    return mounted_secret_scenario()


@pytest.fixture
def pivot():
    return pivot_scenario()
