from typing import ClassVar

import pytest

from px import config, main


class ImmediateThread:
    def __init__(self, target, args=(), kwargs=None):
        self.target = target
        self.args = args
        self.kwargs = kwargs or {}
        self.daemon = False

    def start(self):
        self.target(*self.args, **self.kwargs)

    def join(self):
        pass


class FakeCurl:
    results: ClassVar[list[int]] = []
    codes: ClassVar[list[int]] = []
    calls: ClassVar[int] = 0
    instances: ClassVar[list["FakeCurl"]] = []

    def __init__(self, url, method):
        self.url = url
        self.method = method
        self.data = ""
        self.ret = self.results.pop(0)
        self.code = type(self).codes.pop(0) if type(self).codes else 200
        self.proxy_host = None
        self.proxy_port = None
        self.setopt_calls = []
        type(self).calls += 1
        type(self).instances.append(self)

    def set_proxy(self, host, port=0, *_args):
        self.proxy_host = host
        self.proxy_port = port

    def setopt(self, option, value):
        self.setopt_calls.append((option, value))

    def set_insecure(self, *_args):
        pass

    def set_debug(self, *_args):
        pass

    def buffer(self, data=b""):
        self.data = data.decode()

    def set_headers(self, *_args):
        pass

    def set_useragent(self, *_args):
        pass

    def perform(self):
        return self.ret

    def get_data(self):
        return self.url + self.data

    def get_headers(self):
        return ""

    def get_response_code(self):
        return self.code

    @property
    def errstr(self):
        return "test failure"


class FakeWproxy:
    def __init__(self, mode, servers):
        self.mode = mode
        self.servers = servers


class FakeLibcurl:
    CURLOPT_RESOLVE = "CURLOPT_RESOLVE"

    def __init__(self):
        self.appended = []
        self.freed = []

    def curl_slist_append(self, _head, value):
        self.appended.append(value)
        return f"slist:{value}"

    def curl_slist_free_all(self, lst):
        self.freed.append(lst)


class FakeFfi:
    NULL = None


class FakeConfig:
    def getint(self, _section, _option):
        return 3128

    def set(self, *_args):
        pass


@pytest.mark.parametrize(
    ("results", "exit_code", "passed"),
    [([0, 0, 0, 0, 0], config.ERROR_SUCCESS, 5), ([0, 0, 1, 0, 0], config.ERROR_TEST, 4)],
)
def test_all_test_reports_each_result(monkeypatch, results, exit_code, passed):
    output = []
    FakeCurl.results = results
    FakeCurl.codes = []
    FakeCurl.calls = 0
    FakeCurl.instances = []

    monkeypatch.setattr(main.config, "get_listen", lambda: "127.0.0.1")
    monkeypatch.setattr(main.STATE, "config", FakeConfig())
    monkeypatch.setattr(main.socket, "create_connection", lambda *_args: None)
    monkeypatch.setattr(main.mcurl, "Curl", FakeCurl)
    monkeypatch.setattr(main.handler, "set_curl_auth", lambda *_args: None)
    monkeypatch.setattr(main.threading, "Thread", ImmediateThread)
    monkeypatch.setattr(main, "pprint", output.append)
    monkeypatch.setattr(main.os, "_exit", lambda code: (_ for _ in ()).throw(SystemExit(code)))

    with pytest.raises(SystemExit) as exc_info:
        main.test("all:http://example.test/")

    assert exc_info.value.code == exit_code
    assert FakeCurl.calls == 5
    assert output.count("Passed") == passed
    if exit_code == config.ERROR_TEST:
        assert "Failed with error 1\ntest failure" in output


@pytest.mark.parametrize(
    ("codes", "exit_code", "passed"),
    [([200, 200, 200, 200, 200], config.ERROR_SUCCESS, 5), ([200, 200, 401, 200, 200], config.ERROR_TEST, 4)],
)
def test_all_test_fails_on_auth_status(monkeypatch, codes, exit_code, passed):
    output = []
    FakeCurl.results = [0] * len(codes)
    FakeCurl.codes = list(codes)
    FakeCurl.calls = 0
    FakeCurl.instances = []

    monkeypatch.setattr(main.config, "get_listen", lambda: "127.0.0.1")
    monkeypatch.setattr(main.STATE, "config", FakeConfig())
    monkeypatch.setattr(main.socket, "create_connection", lambda *_args: None)
    monkeypatch.setattr(main.mcurl, "Curl", FakeCurl)
    monkeypatch.setattr(main.handler, "set_curl_auth", lambda *_args: None)
    monkeypatch.setattr(main.threading, "Thread", ImmediateThread)
    monkeypatch.setattr(main, "pprint", output.append)
    monkeypatch.setattr(main.os, "_exit", lambda code: (_ for _ in ()).throw(SystemExit(code)))

    with pytest.raises(SystemExit) as exc_info:
        main.test("all:http://example.test/")

    assert exc_info.value.code == exit_code
    assert FakeCurl.calls == 5
    assert output.count("Passed") == passed
    if exit_code == config.ERROR_TEST:
        assert any("status 401" in line for line in output)


def test_single_url_test_fails_on_407(monkeypatch):
    output = []
    FakeCurl.results = [0]
    FakeCurl.codes = [407]
    FakeCurl.calls = 0
    FakeCurl.instances = []

    monkeypatch.setattr(main.config, "get_listen", lambda: "127.0.0.1")
    monkeypatch.setattr(main.STATE, "config", FakeConfig())
    monkeypatch.setattr(main.socket, "create_connection", lambda *_args: None)
    monkeypatch.setattr(main.mcurl, "Curl", FakeCurl)
    monkeypatch.setattr(main.handler, "set_curl_auth", lambda *_args: None)
    monkeypatch.setattr(main.threading, "Thread", ImmediateThread)
    monkeypatch.setattr(main, "pprint", output.append)
    monkeypatch.setattr(main.os, "_exit", lambda code: (_ for _ in ()).throw(SystemExit(code)))

    with pytest.raises(SystemExit) as exc_info:
        main.test("http://example.test/")

    assert exc_info.value.code == config.ERROR_TEST
    assert "Passed" not in output
    assert any("status 407" in line for line in output)


##
# --test-auth Negotiate SPN addressing (px/main.py:_negotiate_test_target)


def _wp_cases():
    return [
        (None, ("127.0.0.2", None, False)),
        (
            FakeWproxy(main.wproxy.MODE_CONFIG_PAC, ["http://example.test/proxy.pac"]),
            ("127.0.0.2", None, False),
        ),
        (
            FakeWproxy(main.wproxy.MODE_CONFIG, [("proxy1.corp.test", 3128), ("proxy2.corp.test", 3128)]),
            ("127.0.0.2", None, False),
        ),
        (FakeWproxy(main.wproxy.MODE_ENV, [("proxy.corp.test", 3128)]), ("127.0.0.2", None, False)),
        (
            FakeWproxy(main.wproxy.MODE_CONFIG, [("proxy.corp.test", 3128)]),
            ("proxy.corp.test", "proxy.corp.test:3128:127.0.0.2", True),
        ),
        (FakeWproxy(main.wproxy.MODE_CONFIG, [("127.0.0.2", 3128)]), ("127.0.0.2", None, True)),
    ]


@pytest.mark.parametrize(("wp", "expected"), _wp_cases())
def test_negotiate_test_target(wp, expected):
    assert main._negotiate_test_target(wp, "127.0.0.2", 3128) == expected


def test_test_auth_negotiate_single_proxy_uses_upstream_host_and_resolve(monkeypatch):
    output = []
    FakeCurl.results = [0]
    FakeCurl.codes = [200]
    FakeCurl.calls = 0
    FakeCurl.instances = []
    fake_libcurl = FakeLibcurl()

    monkeypatch.setattr(main.config, "get_listen", lambda: "127.0.0.2")
    monkeypatch.setattr(main.STATE, "config", FakeConfig())
    monkeypatch.setattr(main.STATE, "auth", "NEGOTIATE")
    monkeypatch.setattr(main.STATE, "wproxy", FakeWproxy(main.wproxy.MODE_CONFIG, [("proxy.corp.test", 3128)]))
    monkeypatch.setattr(main.socket, "create_connection", lambda *_args: None)
    monkeypatch.setattr(main.mcurl, "Curl", FakeCurl)
    monkeypatch.setattr(main.mcurl, "libcurl", fake_libcurl)
    monkeypatch.setattr(main.mcurl, "ffi", FakeFfi())
    monkeypatch.setattr(main.mcurl, "py2cstr", lambda s: s)
    monkeypatch.setattr(main.handler, "set_curl_auth", lambda *_args: None)
    monkeypatch.setattr(main.threading, "Thread", ImmediateThread)
    monkeypatch.setattr(main, "pprint", output.append)
    monkeypatch.setattr(main.os, "_exit", lambda code: (_ for _ in ()).throw(SystemExit(code)))
    monkeypatch.setattr(main.sys, "argv", ["px", "--test-auth"])

    with pytest.raises(SystemExit) as exc_info:
        main.test("http://example.test/")

    assert exc_info.value.code == config.ERROR_SUCCESS
    curl = FakeCurl.instances[-1]
    assert (curl.proxy_host, curl.proxy_port) == ("proxy.corp.test", 3128)
    assert fake_libcurl.appended == ["proxy.corp.test:3128:127.0.0.2"]
    assert curl.setopt_calls == [(fake_libcurl.CURLOPT_RESOLVE, "slist:proxy.corp.test:3128:127.0.0.2")]
    assert fake_libcurl.freed == ["slist:proxy.corp.test:3128:127.0.0.2"]
    assert not any("single explicit --proxy" in line for line in output)


def test_test_auth_without_single_proxy_warns_and_keeps_listen(monkeypatch):
    output = []
    FakeCurl.results = [0]
    FakeCurl.codes = [200]
    FakeCurl.calls = 0
    FakeCurl.instances = []

    monkeypatch.setattr(main.config, "get_listen", lambda: "127.0.0.2")
    monkeypatch.setattr(main.STATE, "config", FakeConfig())
    monkeypatch.setattr(main.STATE, "auth", "NEGOTIATE")
    monkeypatch.setattr(
        main.STATE, "wproxy", FakeWproxy(main.wproxy.MODE_CONFIG_PAC, ["http://example.test/proxy.pac"])
    )
    monkeypatch.setattr(main.socket, "create_connection", lambda *_args: None)
    monkeypatch.setattr(main.mcurl, "Curl", FakeCurl)
    monkeypatch.setattr(main.handler, "set_curl_auth", lambda *_args: None)
    monkeypatch.setattr(main.threading, "Thread", ImmediateThread)
    monkeypatch.setattr(main, "pprint", output.append)
    monkeypatch.setattr(main.os, "_exit", lambda code: (_ for _ in ()).throw(SystemExit(code)))
    monkeypatch.setattr(main.sys, "argv", ["px", "--test-auth"])

    with pytest.raises(SystemExit) as exc_info:
        main.test("http://example.test/")

    assert exc_info.value.code == config.ERROR_SUCCESS
    curl = FakeCurl.instances[-1]
    assert curl.proxy_host == "127.0.0.2"
    assert curl.setopt_calls == []
    assert any("single explicit --proxy" in line for line in output)
