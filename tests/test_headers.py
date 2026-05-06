"""Tests for ``build_www_authenticate``."""

from __future__ import annotations

from phase_platform_auth import build_www_authenticate
from phase_platform_auth.headers import DEFAULT_REALM


def test_default_realm_is_m2020_phase() -> None:
    """§2.6.1: default realm for the PHASE Platform is 'm2020-phase'."""
    assert DEFAULT_REALM == "m2020-phase"


def test_default_header() -> None:
    headers = build_www_authenticate()
    assert headers == {"WWW-Authenticate": 'Bearer realm="m2020-phase"'}


def test_custom_realm() -> None:
    headers = build_www_authenticate(realm="staging")
    assert headers == {"WWW-Authenticate": 'Bearer realm="staging"'}
