"""Tests for non-blocking PAC DNS resolution."""

import asyncio
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from px import config, handler, resolver


def test_my_ip_address_does_not_use_dns(monkeypatch):
    class ProbeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def connect(self, address):
            assert address == ("192.0.2.1", 9)

        def getsockname(self):
            return ("198.51.100.10", 12345)

    def hangs_if_called(*_):
        raise AssertionError

    monkeypatch.setattr(resolver.socket, "socket", lambda *_: ProbeSocket())
    monkeypatch.setattr(resolver.socket, "gethostname", hangs_if_called)
    monkeypatch.setattr(resolver.socket, "getaddrinfo", hangs_if_called)

    start = time.monotonic()
    assert resolver.my_ip_address() == "198.51.100.10"
    assert time.monotonic() - start < 0.1


def test_my_ip_address_falls_back_to_first_non_local_address(monkeypatch):
    class NoRouteSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def connect(self, _):
            raise OSError

    class Address:
        def __init__(self, value, loopback=False, link_local=False):
            self.value = value
            self.loopback = loopback
            self.link_local = link_local

        def __str__(self):
            return self.value

        def is_loopback(self):
            return self.loopback

        def is_link_local(self):
            return self.link_local

    monkeypatch.setattr(resolver.socket, "socket", lambda *_: NoRouteSocket())
    monkeypatch.setattr(
        config,
        "get_host_ips",
        lambda: [
            Address("127.0.0.1", loopback=True),
            Address("169.254.10.1", link_local=True),
            Address("10.0.0.10"),
        ],
    )

    assert resolver.my_ip_address() == "10.0.0.10"


def test_my_ip_address_falls_back_to_loopback(monkeypatch):
    class NoRouteSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def connect(self, _):
            raise OSError

    monkeypatch.setattr(resolver.socket, "socket", lambda *_: NoRouteSocket())
    monkeypatch.setattr(config, "get_host_ips", lambda: [])

    assert resolver.my_ip_address() == "127.0.0.1"


def test_resolver_caches_positive_results(monkeypatch):
    calls = 0

    def getaddrinfo(*_):
        nonlocal calls
        calls += 1
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.25", 0))]

    monkeypatch.setattr(resolver.socket, "getaddrinfo", getaddrinfo)
    dns = resolver.Resolver()
    try:
        assert dns.lookup("cache.example") == "192.0.2.25"
        assert dns.lookup("cache.example") == "192.0.2.25"
        assert calls == 1
    finally:
        dns.close()


def test_resolver_caches_failures_until_negative_ttl_expires(monkeypatch):
    clock = [0.0]
    calls = 0

    def getaddrinfo(*_):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise socket.gaierror()
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.26", 0))]

    monkeypatch.setattr(resolver.socket, "getaddrinfo", getaddrinfo)
    dns = resolver.Resolver(negative_ttl=10.0, clock=lambda: clock[0])
    try:
        assert dns.lookup("negative.example") is None
        clock[0] = 9.9
        assert dns.lookup("negative.example") is None
        assert calls == 1
        clock[0] = 10.0
        assert dns.lookup("negative.example") == "192.0.2.26"
        assert calls == 2
    finally:
        dns.close()


def test_resolver_deduplicates_inflight_lookup(monkeypatch):
    entered = threading.Event()
    release = threading.Event()
    calls = 0

    def getaddrinfo(*_):
        nonlocal calls
        calls += 1
        entered.set()
        assert release.wait(1)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.27", 0))]

    monkeypatch.setattr(resolver.socket, "getaddrinfo", getaddrinfo)
    dns = resolver.Resolver()
    try:
        with ThreadPoolExecutor(max_workers=2) as callers:
            first = callers.submit(dns.lookup, "dedupe.example", socket.AF_INET, 1)
            assert entered.wait(1)
            second = callers.submit(dns.lookup, "dedupe.example", socket.AF_INET, 1)
            release.set()
            assert first.result() == "192.0.2.27"
            assert second.result() == "192.0.2.27"
        assert calls == 1
    finally:
        dns.close()


def test_resolver_timeout_allows_late_cache_fill(monkeypatch):
    release = threading.Event()

    def getaddrinfo(*_):
        assert release.wait(1)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.28", 0))]

    monkeypatch.setattr(resolver.socket, "getaddrinfo", getaddrinfo)
    dns = resolver.Resolver()
    try:
        assert dns.lookup("slow.example", timeout=0.01) is None
        release.set()
        assert dns.lookup("slow.example", timeout=1) == "192.0.2.28"
    finally:
        dns.close()


def test_resolver_pool_is_bounded():
    dns = resolver.Resolver()
    try:
        assert dns._executor._max_workers == resolver.POOL_WORKERS
    finally:
        dns.close()


def test_resolver_returns_ipv6_literal_without_dns(monkeypatch):
    monkeypatch.setattr(
        resolver.socket,
        "getaddrinfo",
        lambda *_: (_ for _ in ()).throw(AssertionError("literal must not be resolved")),
    )
    dns = resolver.Resolver()
    try:
        assert dns.lookup("2001:db8::1", socket.AF_INET6) == "2001:db8::1"
    finally:
        dns.close()


def test_resolver_keeps_all_unspecified_family_addresses(monkeypatch):
    def getaddrinfo(*_):
        return [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::8", 0, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.8", 0)),
            (socket.AF_INET6, socket.SOCK_DGRAM, 17, "", ("2001:db8::8", 0, 0, 0)),
        ]

    monkeypatch.setattr(resolver.socket, "getaddrinfo", getaddrinfo)
    dns = resolver.Resolver()
    try:
        assert dns.lookup_all("proxy.example", socket.AF_UNSPEC) == ["2001:db8::8", "192.0.2.8"]
        assert dns.lookup("proxy.example", socket.AF_UNSPEC) == "2001:db8::8"
    finally:
        dns.close()


class ResolveCurl:
    easyhash = "fake"

    def __init__(self):
        self.options = []

    def setopt(self, option, value):
        self.options.append((option, value))


class ResolveLibcurl:
    CURLOPT_RESOLVE = "resolve"

    @staticmethod
    def curl_slist_append(_head, value):
        return f"slist:{value}"


class ResolveFfi:
    NULL = None


def _set_proxy_resolve(monkeypatch, addresses):
    calls = []

    class Resolver:
        def lookup_all(self, host, family):
            calls.append((host, family))
            return addresses

    class Wproxy:
        def get_resolver(self):
            return Resolver()

    curl = ResolveCurl()
    connection = handler.ConnectionHandler.__new__(handler.ConnectionHandler)
    connection.curl = curl
    monkeypatch.setattr(handler.STATE, "wproxy", Wproxy())
    monkeypatch.setattr(handler.mcurl, "libcurl", ResolveLibcurl())
    monkeypatch.setattr(handler.mcurl, "ffi", ResolveFfi())
    monkeypatch.setattr(handler.mcurl, "py2cstr", lambda value: value)

    return asyncio.run(connection._set_proxy_resolve("proxy.corp.test", 3128)), calls, curl


def test_proxy_resolution_seeds_temporary_all_address_curl_entry(monkeypatch):
    resolve, calls, curl = _set_proxy_resolve(monkeypatch, ["192.0.2.8", "2001:db8::8"])

    assert calls == [("proxy.corp.test", socket.AF_UNSPEC)]
    assert resolve == "slist:+proxy.corp.test:3128:192.0.2.8,[2001:db8::8]"
    assert curl.options == [("resolve", resolve)]


def test_proxy_resolution_failure_leaves_curl_dns_unmodified(monkeypatch):
    resolve, calls, curl = _set_proxy_resolve(monkeypatch, None)

    assert calls == [("proxy.corp.test", socket.AF_UNSPEC)]
    assert resolve is None
    assert curl.options == []
