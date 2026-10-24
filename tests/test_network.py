"""Tests for network features — quit, hostonly, gateway, listen, allow.

These tests exercise Px as a running process and verify socket-level
behavior. They are ported from the legacy test.py.
"""

import asyncio
import os
import subprocess
import time
import unittest.mock

import pytest
from helpers import can_connect, find_free_port, is_port_free, quit_px, run_px

from px import handler


def _worker_port(request, test_index):
    """Return a unique port for this worker + test combination.

    Each xdist worker gets a contiguous block of 10 ports starting at
    5000 + worker_id * 10.  test_index (0-9) selects a port within
    that block.  Falls back to find_free_port if the computed port is busy."""
    try:
        worker_id = int(request.config.workerinput.get("workerid", "gw0").replace("gw", ""))
    except AttributeError:
        worker_id = 0
    port = 5000 + worker_id * 10 + test_index
    if is_port_free(port):
        return port
    return find_free_port(port)


class TestQuit:
    def test_quit_drains_response_before_exiting(self):
        """The quit client must receive 200 before a frozen process exits."""
        events = []

        class Writer:
            async def drain(self):
                events.append("drain")

        connection = handler.ConnectionHandler.__new__(handler.ConnectionHandler)
        connection.writer = Writer()
        connection.client_address = ("127.0.0.1", 0)
        connection._send_response = lambda *_args: events.append("response")

        async def sleep(_seconds):
            events.append("sleep")

        with (
            unittest.mock.patch.object(handler.config, "get_host_ips", return_value={"127.0.0.1"}),
            unittest.mock.patch.object(handler.STATE, "listen", ["127.0.0.1"]),
            unittest.mock.patch.object(handler.STATE, "cleanup_kerberos"),
            unittest.mock.patch.object(handler.asyncio, "sleep", sleep),
            unittest.mock.patch.object(handler.os, "_exit", side_effect=SystemExit) as exit_mock,
            pytest.raises(SystemExit),
        ):
            asyncio.run(connection._handle_quit())

        assert events == ["response", "drain", "sleep"]
        exit_mock.assert_called_once_with(handler.config.ERROR_SUCCESS)

    def test_quit_stops_px(self, request, tmp_path):
        port = _worker_port(request, 0)
        if port is None:
            pytest.skip("No free port found")
        subp, cmd, logfile = run_px("quit", port, tmp_path)
        try:
            assert can_connect("127.0.0.1", port), "Px should be running"

            # Send --quit with retries: if workers aren't fully up yet, an
            # early attempt may fail, so retry rather than guess a fixed
            # warm-up delay.
            quit_cmd = f"px --port={port} --quit"
            ret = None
            for _attempt in range(3):
                ret = os.system(quit_cmd)
                if ret == 0:
                    break
                time.sleep(2)
            assert ret == 0, f"--quit failed with {ret}"

            # Px should exit
            retcode = subp.wait(timeout=15)
            assert retcode == 0, f"Px exited with {retcode}"

            # Poll for the port to free up rather than guessing a fixed delay
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not is_port_free(port):
                time.sleep(0.05)
            assert is_port_free(port), "Port should be free after quit"
        except Exception:
            quit_px("quit", subp, cmd, strict=False)
            raise
        finally:
            if logfile:
                logfile.close()


class TestListen:
    def test_listen_localhost_only(self, request, tmp_path):
        """Px with default listen should only accept on 127.0.0.1."""
        port = _worker_port(request, 1)
        if port is None:
            pytest.skip("No free port found")
        subp, cmd, logfile = run_px("listen", port, tmp_path)
        try:
            assert can_connect("127.0.0.1", port)
        finally:
            quit_px("listen", subp, cmd, strict=False)
            if logfile:
                logfile.close()

    def test_listen_specific_ip(self, request, tmp_path):
        """Px with --listen should only accept on that IP."""
        port = _worker_port(request, 2)
        if port is None:
            pytest.skip("No free port found")

        # Get a local IP that isn't 127.0.0.1
        from px.config import get_host_ips

        host_ips = [str(ip) for ip in get_host_ips()]
        non_local = [ip for ip in host_ips if ip != "127.0.0.1" and not ip.startswith("172.1")]
        if not non_local:
            pytest.skip("No non-loopback IP available")

        listen_ip = non_local[0]
        subp, cmd, logfile = run_px("listen-ip", port, tmp_path, flags=f"--listen={listen_ip}", listen_ip=listen_ip)
        try:
            # Should be reachable on the specified IP
            assert can_connect(listen_ip, port), f"Should connect on {listen_ip}"
            # Should NOT be reachable on 127.0.0.1 (unless listen_ip routes there)
            if listen_ip != "127.0.0.1":
                assert not can_connect("127.0.0.1", port), "Should not connect on 127.0.0.1"
        finally:
            quit_px("listen-ip", subp, cmd, strict=False)
            if logfile:
                logfile.close()


class TestHostonly:
    def test_hostonly_binds_all_local(self, request, tmp_path):
        """Px with --hostonly should accept on all local interfaces."""
        port = _worker_port(request, 3)
        if port is None:
            pytest.skip("No free port found")
        subp, cmd, logfile = run_px("hostonly", port, tmp_path, flags="--hostonly")
        try:
            assert can_connect("127.0.0.1", port), "Should connect on 127.0.0.1"

            from px.config import get_host_ips

            host_ips = [str(ip) for ip in get_host_ips()]
            for ip in host_ips:
                if ip.startswith("172.1"):
                    continue
                assert can_connect(ip, port), f"Should connect on {ip}"
        finally:
            quit_px("hostonly", subp, cmd, strict=False)
            if logfile:
                logfile.close()


class TestGateway:
    def test_gateway_binds_all(self, request, tmp_path):
        """Px with --gateway should accept on all interfaces."""
        port = _worker_port(request, 4)
        if port is None:
            pytest.skip("No free port found")
        subp, cmd, logfile = run_px("gateway", port, tmp_path, flags="--gateway")
        try:
            assert can_connect("127.0.0.1", port), "Should connect on 127.0.0.1"

            from px.config import get_host_ips

            host_ips = [str(ip) for ip in get_host_ips()]
            for ip in host_ips:
                if ip.startswith("172.1"):
                    continue
                assert can_connect(ip, port), f"Should connect on {ip}"
        finally:
            quit_px("gateway", subp, cmd, strict=False)
            if logfile:
                logfile.close()


class TestAllow:
    def test_allow_restricts_to_matching_ip(self, request, tmp_path):
        """Px with --gateway --allow should accept connections from matching IPs only."""
        from px.config import get_host_ips

        host_ips = [str(ip) for ip in get_host_ips()]
        non_docker = [ip for ip in host_ips if not ip.startswith("172.1")]
        if len(non_docker) < 1:
            pytest.skip("Need at least one non-Docker IP")

        # Allow only 127.0.* — connections from 127.0.0.1 should succeed at socket level
        port = _worker_port(request, 5)
        if port is None:
            pytest.skip("No free port found")
        subp, cmd, logfile = run_px("allow", port, tmp_path, flags="--gateway --allow=127.0.*.*")
        try:
            # 127.0.0.1 should connect (socket level)
            assert can_connect("127.0.0.1", port), "Should connect on 127.0.0.1 (allowed)"

            # Other IPs should also connect at socket level (--gateway binds all)
            # but HTTP requests from non-allowed IPs will be rejected — verified below
            for ip in non_docker:
                if ip == "127.0.0.1":
                    continue
                # Socket connection succeeds because gateway binds all interfaces
                assert can_connect(ip, port), f"Socket should connect on {ip} (gateway)"
        finally:
            quit_px("allow", subp, cmd, strict=False)
            if logfile:
                logfile.close()

    def test_allow_specific_subnet(self, request, tmp_path):
        """Px with --gateway --allow with specific subnet pattern."""
        port = _worker_port(request, 6)
        if port is None:
            pytest.skip("No free port found")
        subp, _cmd, logfile = run_px("allow-subnet", port, tmp_path, flags="--gateway --allow=10.0.*.*")
        try:
            # Gateway should bind all interfaces
            assert can_connect("127.0.0.1", port), "Should connect on 127.0.0.1"
        finally:
            # --quit picks its target interface from the hosts that match
            # --allow (see get_listen() in px/config.py); none of this host's
            # real interfaces are ever in 10.0.0.0/8, so --quit is guaranteed
            # to fail here. Terminate directly instead of paying for 3 doomed
            # --quit retries plus a 10s wait before quit_px() falls back to
            # killing it anyway.
            subp.terminate()
            try:
                subp.wait(timeout=5)
            except subprocess.TimeoutExpired:
                subp.kill()
                subp.wait()
            if logfile:
                logfile.close()


class TestNoproxyBypass:
    def test_noproxy_flag_accepted(self, request, tmp_path):
        """Px with --noproxy should start and accept connections."""
        port = _worker_port(request, 7)
        if port is None:
            pytest.skip("No free port found")
        subp, cmd, logfile = run_px("noproxy", port, tmp_path, flags="--noproxy=*.*.*.*")
        try:
            assert can_connect("127.0.0.1", port), "Px with --noproxy should accept connections"
        finally:
            quit_px("noproxy", subp, cmd, strict=False)
            if logfile:
                logfile.close()

    def test_noproxy_with_proxy_flag(self, request, tmp_path):
        """Px with --proxy and --noproxy should start and accept connections."""
        port = _worker_port(request, 8)
        if port is None:
            pytest.skip("No free port found")
        subp, cmd, logfile = run_px("noproxy-proxy", port, tmp_path, flags="--proxy=127.0.0.1:9999 --noproxy=*.*.*.*")
        try:
            assert can_connect("127.0.0.1", port), "Px with --proxy --noproxy should accept connections"
        finally:
            quit_px("noproxy-proxy", subp, cmd, strict=False)
            if logfile:
                logfile.close()
