"""Tests for test-harness helpers."""

import os
import struct
import subprocess
import sys

import helpers
import psutil
import pytest
from helpers import px_print_env


class TestPxPrintEnvDiagnostics:
    def test_mapping_values_are_never_logged(self, capsys):
        env = {"PX_PASSWORD": "s3cr3t", "PX_CLIENT_PASSWORD": "als0s3cr3t"}
        px_print_env("px --port=3128", env)
        out = capsys.readouterr().out
        assert "s3cr3t" not in out
        assert "als0s3cr3t" not in out
        assert "PX_PASSWORD=<set>" in out
        assert "PX_CLIENT_PASSWORD=<set>" in out

    def test_non_sensitive_mapping_values_are_not_logged(self, capsys):
        env = {"PX_PORT": "3128", "PX_LISTEN": "127.0.0.1", "PX_TOKEN": "secret"}
        px_print_env("px --port=3128", env)
        out = capsys.readouterr().out
        assert "3128" in out  # The command's port remains useful diagnostic output.
        assert "127.0.0.1" not in out
        assert "secret" not in out
        assert "PX_PORT=<set>" in out
        assert "PX_LISTEN=<set>" in out
        assert "PX_TOKEN=<set>" in out

    def test_cmd_with_password_equals_value_is_redacted(self, capsys):
        px_print_env("px --username=bob --password=s3cr3t --port=3128", {})
        out = capsys.readouterr().out
        assert "s3cr3t" not in out
        assert "--password=***REDACTED***" in out
        assert "--username=bob" in out

    def test_cmd_with_client_password_space_value_is_redacted(self, capsys):
        px_print_env("px --client-password s3cr3t --port=3128", {})
        out = capsys.readouterr().out
        assert "s3cr3t" not in out
        assert "--client-password ***REDACTED***" in out

    def test_cmd_structure_preserved_without_secrets(self, capsys):
        cmd = "px --verbose --port=3128 --config=/tmp/px.ini"
        px_print_env(cmd, {})
        out = capsys.readouterr().out
        assert out.strip() == cmd


def _process_with_child():
    script = (
        "import subprocess, sys, time; "
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
        "print(child.pid, flush=True); time.sleep(60)"
    )
    root = subprocess.Popen(  # noqa: S603 -- process-tree cleanup test fixture
        [sys.executable, "-c", script],
        stdout=subprocess.PIPE,
        text=True,
    )
    assert root.stdout is not None
    child_pid = int(root.stdout.readline())
    return root, child_pid


def test_port_reservation_reclaims_stale_owner_without_signalling(monkeypatch, tmp_path):
    monkeypatch.setattr(helpers.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(helpers, "is_port_free", lambda _port: True)
    path = tmp_path / "px-test-ports-3148-3"
    path.write_text(str(os.getpid()))
    monkeypatch.setattr(helpers.psutil, "pid_exists", lambda pid: pid == os.getpid())
    monkeypatch.setattr(helpers.os, "kill", lambda *_args: pytest.fail("liveness probe must not signal"))

    assert helpers.find_free_port_block() == 3151
    assert path.read_text() == str(os.getpid())

    path.write_text("12345")
    monkeypatch.setattr(helpers.psutil, "pid_exists", lambda _pid: False)
    assert helpers.find_free_port_block() == 3154
    assert not path.exists()
    assert helpers.find_free_port_block() == 3148
    assert path.read_text() == str(os.getpid())


def test_quit_failure_terminates_px_process_tree(monkeypatch):
    root, child_pid = _process_with_child()
    monkeypatch.setattr(helpers.os, "system", lambda _cmd: 1)
    monkeypatch.setattr(helpers.time, "sleep", lambda _seconds: None)

    helpers.quit_px("tree", root, "px", strict=False)

    assert root.poll() is not None
    assert not psutil.pid_exists(child_pid)


def test_failed_startup_terminates_px_process_tree(monkeypatch, tmp_path):
    root, child_pid = _process_with_child()
    monkeypatch.setattr(helpers.subprocess, "Popen", lambda *_args, **_kwargs: root)
    monkeypatch.setattr(
        helpers,
        "is_px_running",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(helpers.PxStartupError("127.0.0.1", 1)),
    )

    with pytest.raises(helpers.PxStartupError):
        helpers.run_px("tree", 3148, tmp_path)

    assert root.poll() is not None
    assert not psutil.pid_exists(child_pid)


def test_run_px_hides_windows_console(monkeypatch, tmp_path):
    recorded = {}

    class FakeProcess:
        pid = 1

    def popen(*_args, **kwargs):
        recorded.update(kwargs)
        return FakeProcess()

    monkeypatch.setattr(helpers.sys, "platform", "win32")
    monkeypatch.setattr(helpers.subprocess, "Popen", popen)
    monkeypatch.setattr(helpers, "is_px_running", lambda *_args: True)
    monkeypatch.setattr(helpers.subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)

    _subp, _cmd, logfile = helpers.run_px("windows", 3148, tmp_path)
    logfile.close()

    assert recorded["creationflags"] == 0x08000000


def test_run_px_keeps_posix_popen_flags_unchanged(monkeypatch, tmp_path):
    recorded = {}

    class FakeProcess:
        pid = 1

    def popen(*_args, **kwargs):
        recorded.update(kwargs)
        return FakeProcess()

    monkeypatch.setattr(helpers.sys, "platform", "linux")
    monkeypatch.setattr(helpers.subprocess, "Popen", popen)
    monkeypatch.setattr(helpers, "is_px_running", lambda *_args: True)

    _subp, _cmd, logfile = helpers.run_px("posix", 3148, tmp_path)
    logfile.close()

    assert "creationflags" not in recorded


class TestNtlmType2:
    """Fake NTLM proxies must offer a challenge current Windows SSPI accepts.

    Windows SSPI on the 2025-11 Windows Server image failed every Type 3 with
    SEC_E_UNSUPPORTED_FUNCTION for an NTLMv1-only challenge (no extended
    session security, 128-bit keys or target info).
    """

    def test_challenge_offers_ntlmv2(self):
        message = helpers.ntlm_type_2()
        assert message[:8] == b"NTLMSSP\x00"
        assert struct.unpack("<I", message[8:12])[0] == 2
        flags = struct.unpack("<I", message[20:24])[0]
        for flag in (0x00080000, 0x00800000, 0x20000000):
            assert flags & flag
        info_len, _, info_offset = struct.unpack("<HHI", message[40:48])
        info = message[info_offset : info_offset + info_len]
        av_ids = []
        while info:
            av_id, av_len = struct.unpack("<HH", info[:4])
            av_ids.append(av_id)
            info = info[4 + av_len :]
        assert av_ids[-1] == 0
        assert {1, 2, 7} <= set(av_ids)

    def test_ntlm_client_builds_type_3(self):
        # On Windows spnego uses SSPI, the provider libcurl uses in px
        spnego = pytest.importorskip("spnego")
        client = spnego.client("ntlm-test", "ntlm-pass", hostname="proxy.example", protocol="ntlm")
        client.step()
        type_3 = client.step(helpers.ntlm_type_2())
        assert type_3[:8] == b"NTLMSSP\x00"
        assert type_3[8:12] == b"\x03\x00\x00\x00"
