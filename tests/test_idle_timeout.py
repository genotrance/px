"""Tests that --idle is applied to plain-HTTP curl handles via set_low_speed."""

import asyncio
import unittest.mock

import pytest

from px import handler


class _Stop(Exception):
    pass


class FakeCurl:
    easyhash = "fake"

    def __init__(self, *args, **kwargs):
        self.low_speed = []

    def set_low_speed(self, limit, seconds):
        self.low_speed.append((limit, seconds))


def _run(method, curl_cls, curl=None):
    h = handler.ConnectionHandler.__new__(handler.ConnectionHandler)
    h.curl = curl
    h._do_client_auth = lambda *a: True
    h.client_authed = False

    async def stop(*a):
        raise _Stop

    h._get_destination = stop
    with (
        unittest.mock.patch.object(handler.mcurl, "Curl", curl_cls),
        unittest.mock.patch.object(handler.STATE, "idle", 42),
        unittest.mock.patch.object(handler.STATE, "client_auth", ()),
        pytest.raises(_Stop),
    ):
        asyncio.run(h._handle_request(method, "http://example.com/", {}, b"", "1.1"))
    return h.curl


def test_plain_http_sets_low_speed():
    assert _run("GET", FakeCurl).low_speed == [(1, 42)]


def test_plain_http_reset_sets_low_speed():
    existing = FakeCurl()
    existing.reset = lambda *a: None
    assert _run("GET", FakeCurl, existing).low_speed == [(1, 42)]


def test_connect_does_not_set_low_speed():
    assert _run("CONNECT", FakeCurl).low_speed == []
