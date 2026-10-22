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
    calls: ClassVar[int] = 0

    def __init__(self, url, method):
        self.url = url
        self.method = method
        self.data = ""
        self.ret = self.results.pop(0)
        type(self).calls += 1

    def set_proxy(self, *_args):
        pass

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

    @property
    def errstr(self):
        return "test failure"


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
    FakeCurl.calls = 0

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
