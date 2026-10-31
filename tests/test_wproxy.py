"""Tests for px.wproxy module — parse_proxy, parse_noproxy, Wproxy basics."""

import asyncio
import socket

import netaddr
import pytest

from px.wproxy import (
    DIRECT,
    MODE_CONFIG,
    MODE_NONE,
    parse_noproxy,
    parse_proxy,
)


class TestParseProxy:
    def test_empty_string(self):
        assert parse_proxy("") == []

    def test_none(self):
        assert parse_proxy(None) == []

    def test_single_host_port(self):
        result = parse_proxy("proxy.example.com:8080")
        assert result == [("proxy.example.com", 8080)]

    def test_single_host_no_port(self):
        result = parse_proxy("proxy.example.com")
        assert result == [("proxy.example.com", 80)]

    def test_multiple_proxies(self):
        result = parse_proxy("proxy1.com:8080, proxy2.com:3128")
        assert result == [("proxy1.com", 8080), ("proxy2.com", 3128)]

    def test_duplicate_proxies(self):
        result = parse_proxy("proxy.com:80, proxy.com:80")
        assert result == [("proxy.com", 80)]

    def test_bad_port_raises(self):
        with pytest.raises(ValueError, match="Bad proxy server port"):
            parse_proxy("proxy.com:notaport")

    def test_whitespace_stripped(self):
        result = parse_proxy("  proxy.com:80 , proxy2.com:3128  ")
        assert result == [("proxy.com", 80), ("proxy2.com", 3128)]


class TestParseNoproxy:
    def test_empty_string(self):
        noproxy, hosts = parse_noproxy("")
        assert noproxy.size == 0
        assert len(hosts) == 0

    def test_none(self):
        noproxy, hosts = parse_noproxy(None)
        assert noproxy.size == 0
        assert len(hosts) == 0

    def test_single_ip(self):
        noproxy, hosts = parse_noproxy("127.0.0.1")
        assert "127.0.0.1" in noproxy
        assert len(hosts) == 0

    def test_cidr(self):
        noproxy, _hosts = parse_noproxy("10.0.0.0/8")
        assert "10.1.2.3" in noproxy
        assert "192.168.1.1" not in noproxy

    def test_ip_range(self):
        noproxy, _hosts = parse_noproxy("192.168.1.1-192.168.1.10")
        assert "192.168.1.5" in noproxy
        assert "192.168.1.11" not in noproxy

    def test_wildcard(self):
        noproxy, _hosts = parse_noproxy("192.168.*.*")
        assert "192.168.1.1" in noproxy
        assert "10.0.0.1" not in noproxy

    def test_hostname(self):
        noproxy, hosts = parse_noproxy("example.com")
        assert "example.com" in hosts
        assert noproxy.size == 0

    def test_mixed_ip_and_hostname(self):
        noproxy, hosts = parse_noproxy("127.0.0.1,example.com,10.0.0.0/8")
        assert "127.0.0.1" in noproxy
        assert "10.1.2.3" in noproxy
        assert "example.com" in hosts

    def test_semicolon_separator(self):
        noproxy, _hosts = parse_noproxy("127.0.0.1;192.168.1.1")
        assert "127.0.0.1" in noproxy
        assert "192.168.1.1" in noproxy

    def test_space_separator(self):
        noproxy, _hosts = parse_noproxy("127.0.0.1 192.168.1.1")
        assert "127.0.0.1" in noproxy
        assert "192.168.1.1" in noproxy

    def test_local_keyword(self):
        noproxy, hosts = parse_noproxy("<local>")
        assert "localhost" in hosts
        assert "127.0.0.1" in noproxy

    def test_iponly_raises_on_hostname(self):
        with pytest.raises(netaddr.core.AddrFormatError):
            parse_noproxy("example.com", iponly=True)

    def test_empty_entries_skipped(self):
        noproxy, _hosts = parse_noproxy("127.0.0.1,,,,192.168.1.1")
        assert "127.0.0.1" in noproxy
        assert "192.168.1.1" in noproxy


class TestWproxyBase:
    """Tests for _WproxyBase / Wproxy class behavior."""

    def test_mode_config_with_servers(self):
        from px.wproxy import _WproxyBase

        w = _WproxyBase(mode=MODE_CONFIG, servers=[("proxy.com", 8080)])
        assert w.mode == MODE_CONFIG
        assert w.servers == [("proxy.com", 8080)]
        assert w.noproxy_hosts_str is None

    def test_mode_none_no_env_proxy(self, monkeypatch):
        monkeypatch.delenv("http_proxy", raising=False)
        monkeypatch.delenv("https_proxy", raising=False)
        monkeypatch.delenv("HTTP_PROXY", raising=False)
        monkeypatch.delenv("HTTPS_PROXY", raising=False)
        # Patch getproxies to return empty
        monkeypatch.setattr("urllib.request.getproxies", lambda: {})
        from px.wproxy import _WproxyBase

        w = _WproxyBase()
        assert w.mode == MODE_NONE

    def test_find_proxy_direct_when_no_proxy(self, monkeypatch):
        monkeypatch.setattr("urllib.request.getproxies", lambda: {})
        from px.wproxy import _WproxyBase

        w = _WproxyBase()
        servers, _netloc, _path = w.find_proxy_for_url("http://example.com")
        assert servers == [DIRECT]

    def test_find_proxy_returns_servers_for_config_mode(self):
        from px.wproxy import _WproxyBase

        w = _WproxyBase(mode=MODE_CONFIG, servers=[("proxy.com", 8080)])
        servers, _netloc, _path = w.find_proxy_for_url("http://example.com")
        assert ("proxy.com", 8080) in servers

    def test_noproxy_bypasses_proxy(self, monkeypatch):
        from px.wproxy import _WproxyBase

        w = _WproxyBase(mode=MODE_CONFIG, servers=[("proxy.com", 8080)], noproxy="127.0.0.1")
        # 127.0.0.1 is an IP so goes into noproxy IPSet, not noproxy_hosts
        assert w.noproxy_hosts_str is None
        monkeypatch.setattr(
            socket, "getaddrinfo", lambda *_: (_ for _ in ()).throw(AssertionError("literal must not be resolved"))
        )
        servers, _netloc, _path = w.find_proxy_for_url("http://127.0.0.1")
        assert servers == [DIRECT]

    def test_noproxy_reuses_resolver_result(self, monkeypatch):
        from px.wproxy import _WproxyBase

        calls = 0

        def getaddrinfo(*_):
            nonlocal calls
            calls += 1
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.25", 0))]

        monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
        w = _WproxyBase(mode=MODE_CONFIG, servers=[("proxy.com", 8080)], noproxy="192.0.2.0/24")
        assert w.check_noproxy_for_netloc(("cache.example", 8080)) == ("192.0.2.25", 8080)
        assert w.check_noproxy_for_netloc(("cache.example", 8080)) == ("192.0.2.25", 8080)
        assert calls == 1

    def test_get_resolver_is_public_and_shared(self):
        from px.wproxy import _WproxyBase

        w = _WproxyBase(mode=MODE_CONFIG, servers=[("proxy.com", 8080)])
        assert w.get_resolver() is w.get_resolver()

    def test_noproxy_unresolvable_host_uses_proxy(self, monkeypatch):
        from px.wproxy import _WproxyBase

        monkeypatch.setattr(socket, "getaddrinfo", lambda *_: (_ for _ in ()).throw(socket.gaierror()))
        w = _WproxyBase(mode=MODE_CONFIG, servers=[("proxy.com", 8080)], noproxy="192.0.2.0/24")
        assert w.check_noproxy_for_netloc(("missing.example", 80)) is None
        servers, netloc, _path = w.find_proxy_for_url("http://missing.example")
        assert servers == [("proxy.com", 8080)]
        assert netloc == ("missing.example", 80)

    def test_async_noproxy_ip_literal_runs_inline_without_pac(self, monkeypatch):
        from px.wproxy import _WproxyBase

        async def to_thread(*_args, **_kwargs):
            raise AssertionError()

        monkeypatch.setattr(asyncio, "to_thread", to_thread)
        w = _WproxyBase(mode=MODE_CONFIG, servers=[("proxy.com", 8080)], noproxy="127.0.0.1")
        servers, netloc, _path = asyncio.run(w.async_find_proxy_for_url("http://127.0.0.1"))
        assert servers == [DIRECT]
        assert netloc == ("127.0.0.1", 80)

    def test_noproxy_hosts_str_cached(self):
        from px.wproxy import _WproxyBase

        w = _WproxyBase(mode=MODE_CONFIG, servers=[("proxy.com", 8080)], noproxy="localhost,intranet.local")
        assert w.noproxy_hosts_str is not None
        assert "localhost" in w.noproxy_hosts_str
        assert "intranet.local" in w.noproxy_hosts_str

    def test_get_netloc_with_port(self):
        from px.wproxy import _WproxyBase

        w = _WproxyBase()
        netloc, path = w.get_netloc("http://example.com:8080/path")
        assert netloc == ("example.com", 8080)
        assert path == "/path"

    def test_get_netloc_http_default_port(self):
        from px.wproxy import _WproxyBase

        w = _WproxyBase()
        netloc, _path = w.get_netloc("http://example.com/page")
        assert netloc == ("example.com", 80)

    def test_get_netloc_https_default_port(self):
        from px.wproxy import _WproxyBase

        w = _WproxyBase()
        netloc, _path = w.get_netloc("https://example.com/page")
        assert netloc == ("example.com", 443)

    def test_get_netloc_preserves_query(self):
        from px.wproxy import _WproxyBase

        w = _WproxyBase()
        _netloc, path = w.get_netloc("http://example.com/path?key=val")
        assert "?key=val" in path
