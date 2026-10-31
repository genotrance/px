"""Unit tests for downstream proxy authentication failures and handshakes."""

import asyncio
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


def test_ntlm_continuation_uses_existing_server_context():
    connection, _responses = _connection()
    context = unittest.mock.Mock(step=unittest.mock.Mock(return_value=None))
    connection.client_ctxt = context
    connection.client_ctxt_scheme = "NTLM"
    token = base64.b64encode(b"NTLMSSP\x00\x03\x00\x00\x00").decode("ascii")

    with unittest.mock.patch.object(handler.spnego.auth, "server") as server:
        assert connection._do_spnego_auth(f"NTLM {token}", "NTLM")

    context.step.assert_called_once_with(base64.b64decode(token))
    server.assert_not_called()
    assert connection.client_ctxt is None
    assert connection.client_ctxt_scheme is None


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


def test_client_password_lookup_is_cached_after_first_success():
    "NTLM/Digest validate credentials on the event loop thread; repeat handshakes must not re-hit the keyring"
    handler._client_password_cache.clear()
    try:
        with unittest.mock.patch.object(handler.keyring, "get_password", return_value="secret") as get_password:
            assert handler.get_client_password("alice") == "secret"
            assert handler.get_client_password("alice") == "secret"
            assert handler.get_client_password("alice") == "secret"
        get_password.assert_called_once_with(handler.CLIENT_REALM, "alice")
    finally:
        handler._client_password_cache.clear()


def test_client_password_lookup_failure_is_not_cached():
    "A missing keyring entry must be retried, not latched as a permanent failure"
    handler._client_password_cache.clear()
    try:
        with unittest.mock.patch.object(handler.keyring, "get_password", side_effect=[None, "secret"]) as get_password:
            assert handler.get_client_password("bob") is None
            assert handler.get_client_password("bob") == "secret"
        assert get_password.call_count == 2
    finally:
        handler._client_password_cache.clear()


def test_client_password_cache_hit_skips_lookup():
    handler._client_password_cache.clear()
    handler._client_password_cache["carol"] = "cached"
    try:
        with unittest.mock.patch.object(handler.keyring, "get_password") as get_password:
            assert handler.get_client_password("carol") == "cached"
        get_password.assert_not_called()
    finally:
        handler._client_password_cache.clear()


def test_failed_basic_auth_invalidates_cached_password_and_rereads():
    handler._client_password_cache.clear()
    connection, _responses = _connection()
    credentials = base64.b64encode(b"dave:new").decode("ascii")
    try:
        with (
            unittest.mock.patch.object(handler.STATE, "client_auth", ["BASIC"]),
            unittest.mock.patch.object(handler.keyring, "get_password", side_effect=["old", "new"]) as get_password,
        ):
            assert handler.get_client_password("dave") == "old"
            assert not connection._do_basic_auth(f"Basic {credentials}")
            assert "dave" not in handler._client_password_cache
            assert connection._do_basic_auth(f"Basic {credentials}")
        assert get_password.call_count == 2
        assert handler._client_password_cache["dave"] == "new"
    finally:
        handler._client_password_cache.clear()


def test_invalidate_client_password_unknown_user_is_noop():
    handler._client_password_cache.clear()
    handler.invalidate_client_password("nobody")
    assert handler._client_password_cache == {}


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


class _HeldBody:
    "Stands in for a RequestBody whose client still waits for 100 Continue"

    def __init__(self, held_back=True):
        self.held_back = held_back
        self.released = 0

    def release(self):
        self.released += 1


def _held_connection(held_back=True):
    connection, responses = _connection()
    connection._request_body = _HeldBody(held_back)
    return connection, responses


def _header_names(response):
    return [name for name, _ in response[1]]


def test_held_back_407_without_handshake_closes_connection():
    connection, responses = _held_connection()

    with unittest.mock.patch.object(handler.STATE, "client_auth", ["NTLM"]):
        connection._send_auth_challenge()

    assert connection._close_after_response
    assert ("Connection", "close") in responses[0][1]
    assert "Proxy-Connection" not in _header_names(responses[0])
    assert connection._request_body.released == 0


def test_held_back_407_mid_handshake_releases_body_and_keeps_connection():
    connection, responses = _held_connection()
    connection.client_ctxt = unittest.mock.Mock()

    with unittest.mock.patch.object(handler.STATE, "client_auth", ["NTLM"]):
        connection._send_auth_challenge(authtype="NTLM", challenge="Y2hhbGxlbmdl")

    assert not connection._close_after_response
    assert ("Proxy-Connection", "Keep-Alive") in responses[0][1]
    assert "Connection" not in _header_names(responses[0])
    assert connection._request_body.released == 1


def test_407_with_sent_body_keeps_connection_without_release():
    connection, responses = _held_connection(held_back=False)

    with unittest.mock.patch.object(handler.STATE, "client_auth", ["NTLM"]):
        connection._send_auth_challenge()

    assert not connection._close_after_response
    assert ("Proxy-Connection", "Keep-Alive") in responses[0][1]
    assert connection._request_body.released == 0


class _Transport:
    def __init__(self):
        self.written = []
        self.closed = False

    def is_closing(self):
        return self.closed

    def write(self, data):
        self.written.append(data)


class _Writer:
    def __init__(self):
        self.transport = _Transport()

    def get_extra_info(self, _name):
        return ("127.0.0.1", 12345)

    def close(self):
        self.transport.closed = True

    async def wait_closed(self):
        pass


LATE_BODY = b"GET http://origin.test/late HTTP/1.1\r\nHost: origin.test\r\n\r\n"
NTLM_TYPE_ONE = base64.b64encode(b"NTLMSSP\x00\x01\x00\x00\x00").decode("ascii")


def _expect_head(*headers):
    lines = ["POST http://origin.test/up HTTP/1.1", "Host: origin.test", *headers]
    lines += [f"Content-Length: {len(LATE_BODY)}", "Expect: 100-continue"]
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


async def _settle():
    for _ in range(20):
        await asyncio.sleep(0)


def _drive(script):
    "Run ConnectionHandler.handle() against an in-memory client; script(reader, transport) plays the client"
    writer = _Writer()
    outcome = {}

    async def main():
        reader = asyncio.StreamReader()
        connection = handler.ConnectionHandler(reader, writer)
        task = asyncio.ensure_future(connection.handle())
        await script(reader, writer.transport, task)
        reader.feed_eof()
        await asyncio.wait_for(task, 5)
        outcome["done"] = True

    with (
        unittest.mock.patch.object(handler.STATE, "client_auth", ["NTLM"]),
        unittest.mock.patch.object(handler.spnego.auth, "server") as server,
    ):
        server.return_value.step.return_value = b"challenge"
        asyncio.run(main())
    return b"".join(writer.transport.written)


def test_late_body_after_held_back_initial_407_is_never_parsed_as_request():
    states = {}

    async def script(reader, transport, task):
        reader.feed_data(_expect_head())
        await _settle()
        states["after_407"] = task.done()
        reader.feed_data(LATE_BODY)
        await _settle()

    wire = _drive(script)

    assert states["after_407"], "the connection must close instead of waiting for another request"
    assert wire.count(b"HTTP/1.1 407") == 1
    assert b"Connection: close" in wire and b"100 Continue" not in wire


def test_late_body_after_mid_handshake_407_is_discarded_and_handshake_continues():
    async def script(reader, transport, task):
        reader.feed_data(_expect_head(f"Proxy-Authorization: NTLM {NTLM_TYPE_ONE}"))
        await _settle()
        assert not task.done()
        reader.feed_data(LATE_BODY)
        reader.feed_data(
            f"POST http://origin.test/up HTTP/1.1\r\nHost: origin.test\r\nContent-Length: 0\r\n"
            f"Proxy-Authorization: NTLM {NTLM_TYPE_ONE}\r\n\r\n".encode()
        )
        await _settle()

    wire = _drive(script)

    assert wire.startswith(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 407")
    assert wire.count(b"100 Continue") == 1
    assert wire.count(b"HTTP/1.1 407") == 2
    assert b"Connection: close" not in wire
