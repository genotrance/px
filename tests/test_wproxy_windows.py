"Windows-only tests for Wproxy against a faked WinHTTP"

import ctypes
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="WinHTTP is Windows-only")

PAC_URL = "http://pac.example/proxy.pac"


class FakeWinHttp:
    "Stands in for ctypes.windll.winhttp and records WinHttpGetProxyForUrl calls"

    def __init__(self):
        self._ie = (False, None, None, None)
        self._answer = {"proxy": None, "direct": False, "error": None}
        self.calls = []

        # Plain functions accept attribute assignment (restype, argtypes)
        def get_ie_config(ref):
            ie = ref._obj
            ie.fAutoDetect, ie.lpszAutoConfigUrl, ie.lpszProxy, ie.lpszProxyBypass = self._ie
            return True

        def open_session(*_args):
            return 1

        def get_proxy_for_url(_handle, _url, opts_ref, info_ref):
            opts = opts_ref._obj
            self.calls.append({
                "flags": opts.dwFlags,
                "detect": opts.dwAutoDetectFlags,
                "url": opts.lpszAutoConfigUrl,
            })
            if self._answer["error"] is not None:
                return False
            info = info_ref._obj
            # Imported here: the WinHTTP constants exist in px.wproxy only on win32,
            # so this module must stay importable on Linux
            if self._answer["proxy"] is not None:
                from px.wproxy import WINHTTP_ACCESS_TYPE_NAMED_PROXY

                info.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY
                info.lpszProxy = self._answer["proxy"]
            elif self._answer["direct"]:
                from px.wproxy import WINHTTP_ACCESS_TYPE_NO_PROXY

                info.dwAccessType = WINHTTP_ACCESS_TYPE_NO_PROXY
            return True

        self.WinHttpGetIEProxyConfigForCurrentUser = get_ie_config
        self.WinHttpOpen = open_session
        self.WinHttpGetProxyForUrl = get_proxy_for_url

    def ie(self, auto_detect, script, proxy, bypass):
        "Set what WinHttpGetIEProxyConfigForCurrentUser reports"
        self._ie = (auto_detect, script, proxy, bypass)

    def answer(self, proxy=None, direct=False, error=None):
        "Set what WinHttpGetProxyForUrl returns"
        self._answer = {"proxy": proxy, "direct": direct, "error": error}


@pytest.fixture
def fake_winhttp(monkeypatch):
    fake = FakeWinHttp()

    class FakeWindll:
        winhttp = fake

    monkeypatch.setattr(ctypes, "windll", FakeWindll())
    monkeypatch.setattr(ctypes, "GetLastError", lambda: fake._answer["error"] or 0)
    return fake


def test_auto_detect_with_setup_script_passes_both_flags(fake_winhttp):
    from px.wproxy import (
        WINHTTP_AUTO_DETECT_TYPE_DHCP,
        WINHTTP_AUTO_DETECT_TYPE_DNS_A,
        WINHTTP_AUTOPROXY_AUTO_DETECT,
        WINHTTP_AUTOPROXY_CONFIG_URL,
        Wproxy,
    )

    fake_winhttp.ie(True, PAC_URL, None, None)
    fake_winhttp.answer(proxy="proxy.example:8080")

    servers, _, _ = Wproxy().find_proxy_for_url("https://www.example.com/")

    assert servers == [("proxy.example", 8080)]
    call = fake_winhttp.calls[0]
    assert call["flags"] == WINHTTP_AUTOPROXY_AUTO_DETECT | WINHTTP_AUTOPROXY_CONFIG_URL
    assert call["url"] == PAC_URL
    assert call["detect"] == WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A


@pytest.mark.parametrize("script", [None, ""])
def test_auto_detect_without_setup_script_passes_auto_detect_only(fake_winhttp, script):
    from px.wproxy import WINHTTP_AUTOPROXY_AUTO_DETECT, Wproxy

    fake_winhttp.ie(True, script, None, None)
    fake_winhttp.answer(proxy="proxy.example:8080")

    Wproxy().find_proxy_for_url("https://www.example.com/")

    call = fake_winhttp.calls[0]
    assert call["flags"] == WINHTTP_AUTOPROXY_AUTO_DETECT
    assert call["url"] is None


def test_setup_script_alone_passes_config_url_only(fake_winhttp):
    from px.wproxy import WINHTTP_AUTOPROXY_CONFIG_URL, Wproxy

    fake_winhttp.ie(False, PAC_URL, None, None)
    fake_winhttp.answer(proxy="proxy.example:8080")

    Wproxy().find_proxy_for_url("https://www.example.com/")

    call = fake_winhttp.calls[0]
    assert call["flags"] == WINHTTP_AUTOPROXY_CONFIG_URL
    assert call["url"] == PAC_URL
    assert call["detect"] == 0


@pytest.mark.parametrize(
    ("auto_detect", "script", "error"),
    [
        (True, PAC_URL, 12180),
        (True, None, 12180),
        (False, PAC_URL, 12167),
    ],
)
def test_failed_automatic_setup_falls_back_to_manual_proxy(fake_winhttp, auto_detect, script, error):
    from px.wproxy import Wproxy

    fake_winhttp.ie(auto_detect, script, "manual.example:3128", None)
    fake_winhttp.answer(error=error)

    servers, _, _ = Wproxy().find_proxy_for_url("https://www.example.com/")

    assert servers == [("manual.example", 3128)]


def test_failed_automatic_setup_without_manual_proxy_goes_direct(fake_winhttp):
    from px.wproxy import DIRECT, Wproxy

    fake_winhttp.ie(True, PAC_URL, None, None)
    fake_winhttp.answer(error=12180)

    servers, _, _ = Wproxy().find_proxy_for_url("https://www.example.com/")

    assert servers == [DIRECT]


def test_fallback_parses_per_scheme_manual_proxy(fake_winhttp):
    from px.wproxy import Wproxy

    fake_winhttp.ie(True, PAC_URL, "http=manual.example:3128;https=manual.example:3129;ftp=ftp.example:21", None)
    fake_winhttp.answer(error=12180)

    servers, _, _ = Wproxy().find_proxy_for_url("https://www.example.com/")

    assert servers == [("manual.example", 3128), ("manual.example", 3129)]


def test_fallback_honours_manual_bypass_list(fake_winhttp, monkeypatch):
    from px.resolver import Resolver
    from px.wproxy import DIRECT, Wproxy

    # Host names must decide without DNS; names that do reach the resolver resolve to nothing
    monkeypatch.setattr(Resolver, "lookup", lambda *_args, **_kwargs: None)

    fake_winhttp.ie(True, PAC_URL, "manual.example:3128", "intranet.example;<local>")
    fake_winhttp.answer(error=12180)
    wproxy = Wproxy()

    def servers_for(url):
        return wproxy.find_proxy_for_url(url)[0]

    assert servers_for("http://wiki.intranet.example/") == [DIRECT]
    assert servers_for("http://localhost/") == [DIRECT]
    assert servers_for("http://intranet.example.org/") == [("manual.example", 3128)]


def test_manual_bypass_does_not_apply_when_setup_script_answers(fake_winhttp):
    from px.wproxy import Wproxy

    fake_winhttp.ie(True, PAC_URL, "manual.example:3128", "intranet.example")
    fake_winhttp.answer(proxy="proxy.example:8080")
    wproxy = Wproxy()

    servers, _, _ = wproxy.find_proxy_for_url("http://wiki.intranet.example/")

    assert servers == [("proxy.example", 8080)]
    assert "intranet.example" not in (wproxy.noproxy_hosts_str or "")


def test_setup_script_answering_direct_does_not_fall_back(fake_winhttp):
    from px.wproxy import DIRECT, Wproxy

    fake_winhttp.ie(True, PAC_URL, "manual.example:3128", None)
    fake_winhttp.answer(direct=True)

    servers, _, _ = Wproxy().find_proxy_for_url("https://www.example.com/")

    assert servers == [DIRECT]


def test_manual_proxy_alone_is_unchanged(fake_winhttp):
    from px.wproxy import MODE_MANUAL, Wproxy

    fake_winhttp.ie(False, None, "manual.example:3128", "intranet.example")
    wproxy = Wproxy()

    servers, _, _ = wproxy.find_proxy_for_url("https://www.example.com/")

    assert wproxy.mode == MODE_MANUAL
    assert servers == [("manual.example", 3128)]
    assert "intranet.example" in wproxy.noproxy_hosts_str
    assert fake_winhttp.calls == []


def _fallback_servers(fake_winhttp, bypass, url, proxy="manual.example:3128"):
    from px.wproxy import Wproxy

    fake_winhttp.ie(True, PAC_URL, proxy, bypass)
    fake_winhttp.answer(error=12180)
    return Wproxy().find_proxy_for_url(url)[0]


def test_fallback_honours_manual_bypass_ip_range(fake_winhttp):
    from px.wproxy import DIRECT

    assert _fallback_servers(fake_winhttp, "10.0.0.0/8", "http://10.1.2.3/") == [DIRECT]
    assert _fallback_servers(fake_winhttp, "10.0.0.0/8", "http://192.0.2.1/") == [("manual.example", 3128)]


def test_fallback_host_match_ignores_case(fake_winhttp):
    from px.wproxy import DIRECT

    assert _fallback_servers(fake_winhttp, "intranet.example", "http://Wiki.Intranet.Example/") == [DIRECT]


def test_fallback_bypass_entry_with_leading_dot(fake_winhttp):
    from px.wproxy import DIRECT

    assert _fallback_servers(fake_winhttp, ".intranet.example", "http://wiki.intranet.example/") == [DIRECT]


def test_malformed_manual_proxy_does_not_break_automatic_setup(fake_winhttp):
    from px.wproxy import DIRECT

    servers = _fallback_servers(fake_winhttp, None, "https://www.example.com/", proxy="manual.example:notaport")

    assert servers == [DIRECT]


def test_other_winhttp_errors_do_not_fall_back(fake_winhttp):
    from px.wproxy import Wproxy

    fake_winhttp.ie(True, PAC_URL, "manual.example:3128", None)
    fake_winhttp.answer(error=12002)

    servers, _, _ = Wproxy().find_proxy_for_url("https://www.example.com/")

    assert servers == []


class TestSourceLabeling:
    "find_proxy_for_url() logs which Windows source supplied its result"

    def test_auto_detect_labelled(self, fake_winhttp):
        from px.wproxy import Wproxy

        fake_winhttp.ie(True, None, None, None)
        fake_winhttp.answer(proxy="proxy.example:8080")
        messages = []
        wproxy = Wproxy(debug_print=messages.append)
        messages.clear()
        wproxy.find_proxy_for_url("https://www.example.com/")

        assert any(message.startswith("Source = auto-detect:") for message in messages)

    def test_auto_detect_with_pac_labelled(self, fake_winhttp):
        from px.wproxy import Wproxy

        fake_winhttp.ie(True, PAC_URL, None, None)
        fake_winhttp.answer(proxy="proxy.example:8080")
        messages = []
        wproxy = Wproxy(debug_print=messages.append)
        messages.clear()
        wproxy.find_proxy_for_url("https://www.example.com/")

        assert any(message.startswith("Source = auto-detect or PAC:") for message in messages)

    def test_pac_labelled(self, fake_winhttp):
        from px.wproxy import Wproxy

        fake_winhttp.ie(False, PAC_URL, None, None)
        fake_winhttp.answer(proxy="proxy.example:8080")
        messages = []
        wproxy = Wproxy(debug_print=messages.append)
        messages.clear()
        wproxy.find_proxy_for_url("https://www.example.com/")

        assert any(message.startswith("Source = PAC") for message in messages)

    def test_manual_labelled(self, fake_winhttp):
        from px.wproxy import Wproxy

        fake_winhttp.ie(False, None, "manual.example:3128", None)
        messages = []
        wproxy = Wproxy(debug_print=messages.append)
        messages.clear()
        wproxy.find_proxy_for_url("https://www.example.com/")

        assert any(message.startswith("Source = manual:") for message in messages)

    def test_manual_fallback_labelled(self, fake_winhttp):
        from px.wproxy import Wproxy

        fake_winhttp.ie(True, PAC_URL, "manual.example:3128", None)
        fake_winhttp.answer(error=12180)
        messages = []
        wproxy = Wproxy(debug_print=messages.append)
        messages.clear()
        wproxy.find_proxy_for_url("https://www.example.com/")

        assert any(message.startswith("Source = manual fallback") for message in messages)


class TestWindowsBypassWildcardAndLocal:
    "Windows bypass-list wildcard domains and <local>"

    def test_manual_wildcard_domain_bypasses_subdomains_not_bare_domain(self, fake_winhttp):
        from px.wproxy import DIRECT, Wproxy

        fake_winhttp.ie(False, None, "manual.example:3128", "*.corp.example")
        wproxy = Wproxy()

        assert wproxy.find_proxy_for_url("http://wiki.corp.example/")[0] == [DIRECT]
        assert wproxy.find_proxy_for_url("http://corp.example/")[0] == [("manual.example", 3128)]

    def test_manual_local_bypasses_hostname_without_dot(self, fake_winhttp, monkeypatch):
        from px.resolver import Resolver
        from px.wproxy import DIRECT, Wproxy

        monkeypatch.setattr(Resolver, "lookup", lambda *_args, **_kwargs: None)
        fake_winhttp.ie(False, None, "manual.example:3128", "<local>")
        wproxy = Wproxy()

        assert wproxy.find_proxy_for_url("http://fileserver/")[0] == [DIRECT]
        assert wproxy.find_proxy_for_url("http://fileserver.corp.example/")[0] == [("manual.example", 3128)]

    def test_fallback_wildcard_domain_bypasses_subdomains_not_bare_domain(self, fake_winhttp):
        from px.wproxy import DIRECT

        assert _fallback_servers(fake_winhttp, "*.corp.example", "http://wiki.corp.example/") == [DIRECT]
        assert _fallback_servers(fake_winhttp, "*.corp.example", "http://corp.example/") == [("manual.example", 3128)]

    def test_fallback_local_bypasses_hostname_without_dot(self, fake_winhttp):
        from px.wproxy import DIRECT

        assert _fallback_servers(fake_winhttp, "<local>", "http://fileserver/") == [DIRECT]
        assert _fallback_servers(fake_winhttp, "<local>", "http://fileserver.corp.example/") == [
            ("manual.example", 3128)
        ]
