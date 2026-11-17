"""Regression tests for px #288 and px #289.

px #288: Negotiate failing because libcurl has no Kerberos credentials for the
configured proxy's SPN. pymcurl 8.23.0.4 classifies that failure itself and
reports resp 401 with errstr starting with mcurl.NEGOTIATE_NO_CREDENTIALS; px
prints one actionable message per proxy from that structured result. The
real failure needs Windows SSPI or a corporate KDC, so these tests feed
synthetic mcurl results through the real px.kerberos/px.handler code.

px #289: libcurl's verbose/debug channel must stay off on every px transfer
unless px runs with --debug.
"""

import asyncio
import unittest.mock

import mcurl
import pytest

from px import handler, kerberos, pac, wproxy
from px.config import STATE

PROXY = ("corp-proxy.example", 3128)
PROXY_KEY = "corp-proxy.example:3128"


@pytest.fixture(autouse=True)
def _reset_state():
    "Isolate STATE auth fields and once-per-proxy diagnostic state per test"
    orig = (STATE.kerberos, STATE.username, STATE.curl_features, STATE.auth, STATE.debug)
    STATE.kerberos = False
    STATE.username = ""
    STATE.curl_features = ["SSPI"]
    STATE.auth = "ANY"
    STATE.debug = None
    kerberos.reset_diagnosed_proxies()
    yield
    STATE.kerberos, STATE.username, STATE.curl_features, STATE.auth, STATE.debug = orig
    kerberos.reset_diagnosed_proxies()


class FakeCurl(unittest.mock.MagicMock):
    "Records whether anything enables libcurl's debug channel"

    def __init__(self, *args, **kwargs):
        super().__init__()
        self.easyhash = "fake"
        self.is_connect = True
        self.is_easy = False
        self.resp = 503
        self.errstr = ""
        self.debug_calls = []
        self.debug_opts = []
        self.set_debug = lambda enable=True: self.debug_calls.append(enable)
        self.setopt = lambda opt, *a: self.debug_opts.append(opt)

    def debug_enabled(self):
        verbose = {mcurl.libcurl.CURLOPT_VERBOSE, mcurl.libcurl.CURLOPT_DEBUGFUNCTION}
        return any(self.debug_calls) or bool(verbose & set(self.debug_opts))


def _handle(direct=False, resp=503, errstr="", proxy=PROXY):
    "Run one CONNECT through ConnectionHandler._handle_request with a failing fake transfer"
    curl = FakeCurl()
    h = handler.ConnectionHandler.__new__(handler.ConnectionHandler)
    h.curl = None
    h.client_authed = False
    h._recv_buf = b""
    h.proxy_servers = [proxy]
    h._do_client_auth = lambda *a: True  # type: ignore[method-assign]
    sent = []
    h._send_error = lambda code, msg="": sent.append((code, msg))  # type: ignore[method-assign]

    async def destination(_target):
        return ("192.0.2.10", 443) if direct else None

    async def no_resolve(*_a):
        return None

    h._get_destination = destination  # type: ignore[method-assign]
    h._set_proxy_resolve = no_resolve  # type: ignore[method-assign]

    def do(c):
        c.resp, c.errstr = resp, errstr
        return False

    fake_mcurl = unittest.mock.Mock(do=do)
    with (
        unittest.mock.patch.object(handler.mcurl, "Curl", lambda *a, **k: curl),
        unittest.mock.patch.object(STATE, "mcurl", fake_mcurl, create=True),
        unittest.mock.patch.object(STATE, "wproxy", unittest.mock.Mock(noproxy_hosts_str=""), create=True),
        unittest.mock.patch.object(STATE, "client_auth", ()),
    ):
        asyncio.run(h._handle_request("CONNECT", "example.com:443", {}, {}, None, "1.1"))
    return curl, sent


# -------------------------------------------------------------------
# A. px #289: no libcurl debug channel unless --debug
# -------------------------------------------------------------------


class TestNoImplicitDebug:
    @pytest.mark.parametrize("auth", ["ANY", "NEGOTIATE", "NTLM", "NONE"])
    def test_proxied_transfer_without_debug(self, auth):
        STATE.auth = auth
        curl, _ = _handle(resp=401, errstr=mcurl.NEGOTIATE_NO_CREDENTIALS)
        assert not curl.debug_enabled()

    def test_direct_transfer_without_debug(self):
        curl, _ = _handle(direct=True)
        assert not curl.debug_enabled()

    def test_proxied_transfer_with_debug(self):
        STATE.debug = object()
        curl, _ = _handle()
        assert curl.debug_enabled()

    @pytest.mark.parametrize("debug", [None, object()])
    def test_pac_load_follows_debug(self, debug):
        STATE.debug = debug
        curl = FakeCurl()
        curl.perform = lambda: 7
        p = pac.Pac.__new__(pac.Pac)
        with unittest.mock.patch.object(pac.mcurl, "Curl", lambda *a, **k: curl):
            p._load_url("http://192.0.2.1/proxy.pac")
        assert curl.debug_enabled() is (debug is not None)

    def test_mcurl_debug_print_is_plain_dprint(self):
        assert not hasattr(kerberos, "relay_debug")
        assert not hasattr(kerberos, "watch_proxy_credentials")


# -------------------------------------------------------------------
# B. px #288: guidance from mcurl's structured no-credentials result
# -------------------------------------------------------------------


class TestNoCredentialsGuidance:
    def test_printed_from_structured_result(self, capsys):
        _, sent = _handle(resp=401, errstr=mcurl.NEGOTIATE_NO_CREDENTIALS + "extra; ")
        out = capsys.readouterr().out
        assert PROXY_KEY in out
        assert "klist get HTTP/<proxy host>" in out
        assert "HTTP/<proxy alias>" in out
        assert "--server=<proxy real host>" in out
        assert "--auth=NTLM" in out
        assert sent and sent[0][0] == 401

    def test_printed_without_debug_mode(self, capsys, monkeypatch):
        from px.debug import Debug

        monkeypatch.setattr(Debug, "instance", None)
        _handle(resp=401, errstr=mcurl.NEGOTIATE_NO_CREDENTIALS)
        assert PROXY_KEY in capsys.readouterr().out

    def test_once_per_proxy(self, capsys):
        _handle(resp=401, errstr=mcurl.NEGOTIATE_NO_CREDENTIALS)
        _handle(resp=401, errstr=mcurl.NEGOTIATE_NO_CREDENTIALS)
        assert capsys.readouterr().out.count("rejected Negotiate") == 1
        assert kerberos.proxy_diagnosed(PROXY_KEY)

    def test_each_proxy_gets_its_own(self, capsys):
        _handle(resp=401, errstr=mcurl.NEGOTIATE_NO_CREDENTIALS)
        _handle(resp=401, errstr=mcurl.NEGOTIATE_NO_CREDENTIALS, proxy=("corp-proxy2.example", 8080))
        out = capsys.readouterr().out
        assert PROXY_KEY in out
        assert "corp-proxy2.example:8080" in out

    @pytest.mark.parametrize(
        ("resp", "errstr"),
        [
            (407, "Authentication function returned an error; "),
            (407, "CONNECT tunnel failed, response 407; "),
            (401, "single sign-on failed; "),
            (502, "Timeout was reached; "),
            (407, mcurl.NEGOTIATE_NO_CREDENTIALS),
        ],
    )
    def test_not_printed_for_other_failures(self, capsys, resp, errstr):
        _handle(resp=resp, errstr=errstr)
        assert "rejected Negotiate" not in capsys.readouterr().out
        assert not kerberos.proxy_diagnosed(PROXY_KEY)

    def test_not_printed_for_direct(self, capsys):
        _handle(direct=True, resp=401, errstr=mcurl.NEGOTIATE_NO_CREDENTIALS)
        assert "rejected Negotiate" not in capsys.readouterr().out


# -------------------------------------------------------------------
# C. Bad noproxy definition message names the accepted syntax
# -------------------------------------------------------------------


def test_bad_noproxy_message(monkeypatch):
    messages = []
    monkeypatch.setattr(wproxy, "dprint", messages.append)
    _, noproxy_hosts = wproxy.parse_noproxy("*.corp.example,.good.example,good2.example")
    assert noproxy_hosts == {".good.example", "good2.example"}
    text = " ".join(messages)
    assert "'*.corp.example'" in text
    assert "'.corp.example'" in text
    assert "'corp.example'" in text
