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
