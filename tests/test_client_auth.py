"""Unit tests for downstream proxy authentication failures and handshakes."""

import base64
import unittest.mock

from px import handler


def _connection():
    connection = handler.ConnectionHandler.__new__(handler.ConnectionHandler)
    connection.client_authed = False
    connection.client_ctxt = None
    connection.client_ctxt_scheme = None
    connection.client_address = ("127.0.0.1", 12345)
    connection._close_after_response = False
    responses = []
    connection._send_response = lambda status, headers, body: responses.append((status, headers, body))
    return connection, responses


def _proxy_auth_headers(response):
    return [value for name, value in response[1] if name == "Proxy-Authenticate"]


def test_invalid_negotiate_token_restarts_with_proxy_challenges():
    connection, responses = _connection()

    with unittest.mock.patch.object(handler.STATE, "client_auth", ["NEGOTIATE", "NTLM"]):
        assert not connection._do_spnego_auth("Negotiate invalid", "NEGOTIATE")

    assert connection.client_ctxt is None
    assert connection.client_ctxt_scheme is None
    assert not connection._close_after_response
    assert responses[0][0] == 407
    assert _proxy_auth_headers(responses[0]) == ["Negotiate", "NTLM"]


def test_switching_from_negotiate_to_ntlm_recreates_server_context():
    connection, _responses = _connection()
    contexts = [unittest.mock.Mock(step=unittest.mock.Mock(return_value=b"challenge")) for _ in range(2)]
    ntlm_type_one = base64.b64encode(b"NTLMSSP\x00\x01\x00\x00\x00").decode("ascii")

    with (
        unittest.mock.patch.object(handler.STATE, "client_auth", ["NEGOTIATE", "NTLM"]),
        unittest.mock.patch.object(handler.spnego.auth, "server", side_effect=contexts) as server,
    ):
        assert not connection._do_spnego_auth("Negotiate YQ==", "NEGOTIATE")
        assert not connection._do_spnego_auth(f"NTLM {ntlm_type_one}", "NTLM")

    assert server.call_args_list[0].kwargs["protocol"] == "negotiate"
    assert server.call_args_list[1].kwargs["protocol"] == "ntlm"
    assert connection.client_ctxt is contexts[1]
    assert connection.client_ctxt_scheme == "NTLM"


def test_bad_digest_credentials_restart_with_proxy_challenge():
    connection, responses = _connection()
    digest = (
        'Digest username="user", nonce="nonce", uri="http://example.test/", '
        'nc="00000001", cnonce="cnonce", qop="auth", response="wrong"'
    )

    with (
        unittest.mock.patch.object(handler.STATE, "client_auth", ["DIGEST"]),
        unittest.mock.patch.object(connection, "_verify_digest_nonce", return_value=True),
        unittest.mock.patch.object(handler, "get_client_password", return_value="correct"),
    ):
        assert not connection._do_digest_auth(digest, "GET", {})

    assert not connection._close_after_response
    assert responses[0][0] == 407
    assert _proxy_auth_headers(responses[0])[0].startswith("Digest ")


def test_bad_basic_credentials_restart_with_proxy_challenge():
    connection, responses = _connection()
    credentials = base64.b64encode(b"user:wrong").decode("ascii")

    with (
        unittest.mock.patch.object(handler.STATE, "client_auth", ["BASIC"]),
        unittest.mock.patch.object(handler, "get_client_password", return_value="correct"),
    ):
        assert not connection._do_basic_auth(f"Basic {credentials}")

    assert not connection._close_after_response
    assert responses[0][0] == 407
    assert _proxy_auth_headers(responses[0]) == ['Basic realm="PxClient"']
