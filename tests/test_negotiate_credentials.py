"""Regression tests for px #288 - diagnosing Negotiate failing because libcurl
has no Kerberos credentials for the configured proxy's SPN.

The actual SEC_E_NO_CREDENTIALS/"No credentials are available in the security
package" text is produced by real Windows SSPI (or, for a GSS-API lookalike,
a real corporate KDC) and is not reproducible through a fake upstream proxy
in CI - the text never crosses the wire, it comes from libcurl's internal
verbose/debug channel. These tests exercise the real px.kerberos/px.handler
code with synthetic debug text instead, per the task's instruction to test
without depending on a real corporate environment.
"""

import inspect
import unittest.mock

import pytest

from px import handler, kerberos
from px.handler import set_curl_auth


@pytest.fixture(autouse=True)
def _reset_state():
    "Isolate STATE auth fields and once-per-proxy diagnostic state per test"
    from px.config import STATE

    orig = (STATE.kerberos, STATE.username, STATE.curl_features, STATE.auth)
    kerberos.reset_diagnosed_proxies()
    yield
    STATE.kerberos, STATE.username, STATE.curl_features, STATE.auth = orig
    kerberos.reset_diagnosed_proxies()


def _mock_curl(easyhash="test"):
    mock_curl = unittest.mock.Mock()
    mock_curl.easyhash = easyhash
    return mock_curl


# -------------------------------------------------------------------
# A. set_curl_auth() flags only the SSO/managed-Kerberos + Negotiate case
# -------------------------------------------------------------------


class TestSetCurlAuthWatch:
    def test_sso_negotiate_watches(self):
        from px.config import STATE

        STATE.kerberos = False
        STATE.username = ""
        STATE.curl_features = ["SSPI"]

        assert set_curl_auth(_mock_curl(), "NEGOTIATE") is True

    def test_sso_any_watches(self):
        from px.config import STATE

        STATE.kerberos = False
        STATE.username = ""
        STATE.curl_features = ["SSPI"]

        assert set_curl_auth(_mock_curl(), "ANY") is True

    def test_sso_ntlm_only_does_not_watch(self):
        "NTLM alone never goes through Negotiate, so this failure cannot occur"
        from px.config import STATE

        STATE.kerberos = False
        STATE.username = ""
        STATE.curl_features = ["SSPI"]

        assert set_curl_auth(_mock_curl(), "NTLM") is False

    def test_explicit_username_does_not_watch(self, monkeypatch):
        "Explicit creds are a different libcurl code path than default-identity SSO"
        from px.config import STATE

        STATE.kerberos = False
        STATE.username = "user@REALM"
        STATE.curl_features = ["SSPI"]
        monkeypatch.setenv("PX_PASSWORD", "secret")

        assert set_curl_auth(_mock_curl(), "NEGOTIATE") is False

    def test_auth_none_does_not_watch(self):
        assert set_curl_auth(_mock_curl(), "NONE") is False

    def test_managed_kerberos_negotiate_watches(self):
        from px.config import STATE

        STATE.kerberos = True
        STATE.curl_features = ["GSS-API"]

        assert set_curl_auth(_mock_curl(), "NEGOTIATE") is True

    def test_no_sspi_gssapi_does_not_watch(self):
        from px.config import STATE

        STATE.kerberos = False
        STATE.username = ""
        STATE.curl_features = []

        assert set_curl_auth(_mock_curl(), "NEGOTIATE") is False


# -------------------------------------------------------------------
# B. relay_debug() detection - positive forms
# -------------------------------------------------------------------


class TestRelayDebugPositive:
    def test_detects_sspi_symbol_form(self, capsys):
        kerberos.watch_proxy_credentials("1", "corp-proxy.example:3128")
        kerberos.relay_debug(
            "1: Curl info: schannel: InitializeSecurityContext failed: SEC_E_NO_CREDENTIALS (0x8009030e)"
        )
        out = capsys.readouterr().out
        assert "corp-proxy.example:3128" in out

    def test_detects_human_readable_form(self, capsys):
        kerberos.watch_proxy_credentials("2", "corp-proxy.example:3128")
        kerberos.relay_debug("2: Curl info: schannel: No credentials are available in the security package")
        out = capsys.readouterr().out
        assert "corp-proxy.example:3128" in out

    def test_detection_is_case_insensitive(self, capsys):
        kerberos.watch_proxy_credentials("3", "corp-proxy.example:3128")
        kerberos.relay_debug("3: Curl info: NO CREDENTIALS ARE AVAILABLE IN THE SECURITY PACKAGE")
        out = capsys.readouterr().out
        assert "corp-proxy.example:3128" in out

    def test_message_contains_required_guidance(self, capsys):
        kerberos.watch_proxy_credentials("4", "corp-proxy.example:3128")
        kerberos.relay_debug("4: Curl info: SEC_E_NO_CREDENTIALS")
        out = capsys.readouterr().out
        assert "klist get HTTP/<proxy host>" in out
        assert "HTTP/<proxy alias>" in out
        assert "--server=<proxy real host>" in out
        assert "--auth=NTLM" in out
        assert "no longer falls back to NTLM inside Negotiate" in out


# -------------------------------------------------------------------
# C. relay_debug() detection - negative/nearby cases
# -------------------------------------------------------------------


class TestRelayDebugNegative:
    def test_unwatched_handle_does_not_match(self, capsys):
        "No watch registered (e.g. plain NTLM, explicit creds, DIRECT) - never fires"
        kerberos.relay_debug("9: Curl info: SEC_E_NO_CREDENTIALS")
        assert capsys.readouterr().out == ""

    def test_generic_auth_error_text_does_not_match(self, capsys):
        "curl_easy_strerror(CURLE_AUTH_ERROR) generic text must not false-positive"
        kerberos.watch_proxy_credentials("10", "corp-proxy.example:3128")
        kerberos.relay_debug("10: Curl info: Authentication function returned an error")
        assert capsys.readouterr().out == ""

    def test_sso_failed_message_does_not_match(self, capsys):
        kerberos.watch_proxy_credentials("11", "corp-proxy.example:3128")
        kerberos.relay_debug(
            "11: Curl info: Proxy authentication failed: single sign-on failed, user/password might be required"
        )
        assert capsys.readouterr().out == ""

    def test_network_timeout_does_not_match(self, capsys):
        kerberos.watch_proxy_credentials("12", "corp-proxy.example:3128")
        kerberos.relay_debug("12: Curl info: Connection timed out after 20000 milliseconds")
        assert capsys.readouterr().out == ""

    def test_unrelated_credentials_phrase_does_not_match(self, capsys):
        "GSS-API ticket-cache errors mention credentials too but are a different failure"
        kerberos.watch_proxy_credentials("13", "corp-proxy.example:3128")
        kerberos.relay_debug("13: Curl info: gss_init_sec_context() failed: Credentials cache not found")
        assert capsys.readouterr().out == ""

    def test_relay_still_forwards_every_message_to_dprint(self, monkeypatch):
        "Normal debug logging must be unaffected by the watch/match logic"
        calls = []
        monkeypatch.setattr(kerberos, "dprint", calls.append)
        kerberos.relay_debug("14: Curl info: Connected to corp-proxy.example port 3128")
        assert calls == ["14: Curl info: Connected to corp-proxy.example port 3128"]


# -------------------------------------------------------------------
# D. Once-per-proxy, including multiple proxies
# -------------------------------------------------------------------


class TestOncePerProxy:
    def test_second_occurrence_does_not_reprint(self, capsys):
        proxy = "corp-proxy.example:3128"

        kerberos.watch_proxy_credentials("20", proxy)
        kerberos.relay_debug("20: Curl info: SEC_E_NO_CREDENTIALS")
        first = capsys.readouterr().out
        assert proxy in first

        # A second request on the same (or a reused) handle hits the same proxy
        kerberos.watch_proxy_credentials("21", proxy)
        kerberos.relay_debug("21: Curl info: SEC_E_NO_CREDENTIALS")
        second = capsys.readouterr().out
        assert second == ""

        assert kerberos.proxy_diagnosed(proxy)

    def test_multiple_proxies_each_get_their_own_diagnostic(self, capsys):
        proxy_a = "corp-proxy-a.example:3128"
        proxy_b = "corp-proxy-b.example:8080"

        kerberos.watch_proxy_credentials("30", proxy_a)
        kerberos.relay_debug("30: Curl info: SEC_E_NO_CREDENTIALS")
        out_a = capsys.readouterr().out
        assert proxy_a in out_a
        assert proxy_b not in out_a

        kerberos.watch_proxy_credentials("31", proxy_b)
        kerberos.relay_debug("31: Curl info: SEC_E_NO_CREDENTIALS")
        out_b = capsys.readouterr().out
        assert proxy_b in out_b
        assert proxy_a not in out_b

        assert kerberos.proxy_diagnosed(proxy_a)
        assert kerberos.proxy_diagnosed(proxy_b)

    def test_reused_handle_switching_proxies_rewatches_cleanly(self, capsys):
        "A persistent client connection reuses the same curl easyhash across requests"
        kerberos.watch_proxy_credentials("40", "corp-proxy-a.example:3128")
        kerberos.unwatch_proxy_credentials("40")
        kerberos.watch_proxy_credentials("40", "corp-proxy-b.example:8080")
        kerberos.relay_debug("40: Curl info: SEC_E_NO_CREDENTIALS")
        out = capsys.readouterr().out
        assert "corp-proxy-b.example:8080" in out
        assert "corp-proxy-a.example:3128" not in out


# -------------------------------------------------------------------
# E. Normal runtime logging (no --debug/--verbose needed)
# -------------------------------------------------------------------


class TestRuntimeLogging:
    def test_fires_without_debug_mode(self, capsys, monkeypatch):
        """The diagnostic must reach the normal runtime log even when
        Debug.instance is None (the default - no --debug/--verbose), since
        that is how most users run Px."""
        from px.debug import Debug

        monkeypatch.setattr(Debug, "instance", None)

        from px.config import STATE

        STATE.kerberos = False
        STATE.username = ""
        STATE.curl_features = ["SSPI"]

        mock_curl = _mock_curl("50")
        assert set_curl_auth(mock_curl, "NEGOTIATE") is True

        proxy = "corp-proxy.example:3128"
        kerberos.watch_proxy_credentials(mock_curl.easyhash, proxy)
        try:
            # What mcurl's debug_callback does during STATE.mcurl.do() for this handle
            kerberos.relay_debug(f"{mock_curl.easyhash}: Curl info: schannel: SEC_E_NO_CREDENTIALS (0x8009030e)")
        finally:
            kerberos.unwatch_proxy_credentials(mock_curl.easyhash)

        out = capsys.readouterr().out
        assert proxy in out


# -------------------------------------------------------------------
# F. px --test output shares the same code path as normal runtime
# -------------------------------------------------------------------


class TestSharedWithTestAction:
    def test_handle_request_wires_the_watch_around_mcurl_do(self):
        """px --test drives real traffic through ConnectionHandler._handle_request,
        the same server-side code path used for normal proxied traffic, so
        main.py needs no separate wiring for this diagnostic to reach --test
        output. This guards that coupling against silently breaking apart."""
        source = inspect.getsource(handler.ConnectionHandler._handle_request)
        assert "kerberos.watch_proxy_credentials" in source
        assert "kerberos.unwatch_proxy_credentials" in source

    def test_mcurl_is_wired_to_relay_debug(self):
        "config.py must route mcurl's debug channel through the diagnostic relay"
        from px import config

        source = inspect.getsource(config.State.parse_config)
        assert "kerberos.relay_debug" in source
