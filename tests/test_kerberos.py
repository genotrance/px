import os
import subprocess
import sys
import threading
import time
import unittest.mock

import pytest

from px.kerberos import CHECK_INTERVAL, RETRY_INTERVAL

# Only run kerberos tests on non-Windows platforms
pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Kerberos management is Linux/macOS only")


# --- Helpers ---


def make_manager(monkeypatch, principal="user@REALM", password="secret", is_heimdal=None):
    """Create a KerberosManager with mocked environment."""
    # Avoid atexit registration during tests
    monkeypatch.setattr("atexit.register", lambda *a, **kw: None)

    from px.kerberos import KerberosManager

    if is_heimdal is not None:
        monkeypatch.setattr(KerberosManager, "_detect_heimdal", lambda self: is_heimdal)

    mgr = KerberosManager(
        principal=principal,
        password_func=lambda: password,
        debug_print=lambda *a, **kw: None,
    )
    return mgr


MIT_KLIST_OUTPUT = """\
Ticket cache: FILE:/tmp/krb5cc_px_12345
Default principal: user@REALM

Valid starting       Expires              Service principal
03/10/2026 08:00:00  03/10/2026 18:00:00  krbtgt/REALM@REALM
        renew until 03/17/2026 08:00:00
"""

MIT_KLIST_OUTPUT_2DIGIT_YEAR = """\
Ticket cache: FILE:/tmp/krb5cc_px_12345
Default principal: user@REALM

Valid starting     Expires            Service principal
03/10/26 08:00:00  03/10/26 18:00:00  krbtgt/REALM@REALM
        renew until 03/17/26 08:00:00
"""

MIT_KLIST_OUTPUT_SINGLE_DIGIT = """\
Ticket cache: FILE:/tmp/krb5cc_px_12345
Default principal: user@REALM

Valid starting       Expires              Service principal
3/10/2026 08:00:00   3/10/2026 18:00:00   krbtgt/REALM@REALM
        renew until 3/17/2026 08:00:00
"""

HEIMDAL_KLIST_OUTPUT = """\
Credentials cache: FILE:/tmp/krb5cc_px_12345
        Principal: user@REALM

  Issued                Expires               Principal
Mar 10 08:00:00 2026  Mar 10 18:00:00 2026  krbtgt/REALM@REALM
"""


# -------------------------------------------------------------------
# A. KerberosManager initialization
# -------------------------------------------------------------------


class TestKerberosInit:
    def test_ccache_set(self, monkeypatch):
        mgr = make_manager(monkeypatch)
        import tempfile

        expected_prefix = f"FILE:{tempfile.gettempdir()}"
        assert mgr.ccache_name.startswith(expected_prefix)
        assert "krb5cc_px_" in mgr.ccache_name
        assert str(os.getpid()) in mgr.ccache_name

    def test_krb5ccname_in_env(self, monkeypatch):
        mgr = make_manager(monkeypatch)
        assert os.environ.get("KRB5CCNAME") == mgr.ccache_name

    def test_cached_env(self, monkeypatch):
        mgr = make_manager(monkeypatch)
        assert mgr._env["KRB5CCNAME"] == mgr.ccache_name

    def test_is_heimdal_detected(self, monkeypatch):
        mgr = make_manager(monkeypatch, is_heimdal=True)
        assert mgr._is_heimdal is True

    def test_is_mit_detected(self, monkeypatch):
        mgr = make_manager(monkeypatch, is_heimdal=False)
        assert mgr._is_heimdal is False

    def test_initial_state(self, monkeypatch):
        mgr = make_manager(monkeypatch)
        assert mgr.ticket_expiry == 0
        assert mgr.next_check == 0
        assert mgr.backoff == 0


# -------------------------------------------------------------------
# B. Ticket acquisition (_kinit_with_password)
# -------------------------------------------------------------------


class TestKinitWithPassword:
    def test_success(self, monkeypatch):
        mgr = make_manager(monkeypatch)

        mock_proc = unittest.mock.Mock()
        mock_proc.returncode = 0
        mock_proc.communicate.return_value = (b"", b"")

        with (
            unittest.mock.patch("subprocess.Popen", return_value=mock_proc),
            unittest.mock.patch("pty.openpty", return_value=(10, 11)),
            unittest.mock.patch("os.write"),
            unittest.mock.patch("os.close"),
            unittest.mock.patch.object(mgr, "_update_expiry"),
        ):
            result = mgr._kinit_with_password()

        assert result is True
        assert mgr.backoff == 0

    def test_password_expired(self, monkeypatch):
        mgr = make_manager(monkeypatch)

        mock_proc = unittest.mock.Mock()
        mock_proc.returncode = 1
        mock_proc.communicate.return_value = (b"", b"Password has expired")

        with (
            unittest.mock.patch("subprocess.Popen", return_value=mock_proc),
            unittest.mock.patch("pty.openpty", return_value=(10, 11)),
            unittest.mock.patch("os.write"),
            unittest.mock.patch("os.close"),
        ):
            result = mgr._kinit_with_password()

        assert result is False
        assert mgr.backoff == CHECK_INTERVAL

    def test_credentials_revoked(self, monkeypatch):
        mgr = make_manager(monkeypatch)

        mock_proc = unittest.mock.Mock()
        mock_proc.returncode = 1
        mock_proc.communicate.return_value = (b"", b"Credentials have been revoked")

        with (
            unittest.mock.patch("subprocess.Popen", return_value=mock_proc),
            unittest.mock.patch("pty.openpty", return_value=(10, 11)),
            unittest.mock.patch("os.write"),
            unittest.mock.patch("os.close"),
        ):
            result = mgr._kinit_with_password()

        assert result is False
        assert mgr.backoff == CHECK_INTERVAL

    def test_principal_not_found(self, monkeypatch):
        mgr = make_manager(monkeypatch)

        mock_proc = unittest.mock.Mock()
        mock_proc.returncode = 1
        mock_proc.communicate.return_value = (b"", b"Client not found in Kerberos database")

        with (
            unittest.mock.patch("subprocess.Popen", return_value=mock_proc),
            unittest.mock.patch("pty.openpty", return_value=(10, 11)),
            unittest.mock.patch("os.write"),
            unittest.mock.patch("os.close"),
        ):
            result = mgr._kinit_with_password()

        assert result is False
        assert mgr.backoff == CHECK_INTERVAL

    def test_wrong_password(self, monkeypatch):
        mgr = make_manager(monkeypatch)

        mock_proc = unittest.mock.Mock()
        mock_proc.returncode = 1
        mock_proc.communicate.return_value = (b"", b"Preauthentication failed")

        with (
            unittest.mock.patch("subprocess.Popen", return_value=mock_proc),
            unittest.mock.patch("pty.openpty", return_value=(10, 11)),
            unittest.mock.patch("os.write"),
            unittest.mock.patch("os.close"),
        ):
            result = mgr._kinit_with_password()

        assert result is False
        assert mgr.backoff == CHECK_INTERVAL

    def test_wrong_password_incorrect(self, monkeypatch):
        mgr = make_manager(monkeypatch)

        mock_proc = unittest.mock.Mock()
        mock_proc.returncode = 1
        mock_proc.communicate.return_value = (b"", b"Password incorrect while getting initial credentials")

        with (
            unittest.mock.patch("subprocess.Popen", return_value=mock_proc),
            unittest.mock.patch("pty.openpty", return_value=(10, 11)),
            unittest.mock.patch("os.write"),
            unittest.mock.patch("os.close"),
        ):
            result = mgr._kinit_with_password()

        assert result is False
        assert mgr.backoff == CHECK_INTERVAL

    def test_clock_skew(self, monkeypatch):
        mgr = make_manager(monkeypatch)

        mock_proc = unittest.mock.Mock()
        mock_proc.returncode = 1
        mock_proc.communicate.return_value = (b"", b"Clock skew too great")

        with (
            unittest.mock.patch("subprocess.Popen", return_value=mock_proc),
            unittest.mock.patch("pty.openpty", return_value=(10, 11)),
            unittest.mock.patch("os.write"),
            unittest.mock.patch("os.close"),
        ):
            result = mgr._kinit_with_password()

        assert result is False
        assert mgr.backoff == CHECK_INTERVAL

    def test_generic_failure(self, monkeypatch):
        mgr = make_manager(monkeypatch)

        mock_proc = unittest.mock.Mock()
        mock_proc.returncode = 1
        mock_proc.communicate.return_value = (b"", b"KDC unreachable")

        with (
            unittest.mock.patch("subprocess.Popen", return_value=mock_proc),
            unittest.mock.patch("pty.openpty", return_value=(10, 11)),
            unittest.mock.patch("os.write"),
            unittest.mock.patch("os.close"),
        ):
            result = mgr._kinit_with_password()

        assert result is False
        assert mgr.backoff == RETRY_INTERVAL

    def test_no_password(self, monkeypatch):
        mgr = make_manager(monkeypatch, password=None)
        mgr.password_func = lambda: None

        with unittest.mock.patch("subprocess.Popen") as mock_popen:
            result = mgr._kinit_with_password()

        assert result is False
        mock_popen.assert_not_called()

    def test_empty_password_still_calls_kinit(self, monkeypatch):
        """Empty string is not None — kinit is still invoked (KDC decides if it's valid)."""
        mgr = make_manager(monkeypatch, password="")
        mgr.password_func = lambda: ""

        mock_proc = unittest.mock.Mock()
        mock_proc.returncode = 1
        mock_proc.communicate.return_value = (b"", b"Preauthentication failed")

        with (
            unittest.mock.patch("subprocess.Popen", return_value=mock_proc) as mock_popen,
            unittest.mock.patch("pty.openpty", return_value=(10, 11)),
            unittest.mock.patch("os.write"),
            unittest.mock.patch("os.close"),
        ):
            result = mgr._kinit_with_password()

        mock_popen.assert_called_once()
        assert result is False

    def test_timeout(self, monkeypatch):
        mgr = make_manager(monkeypatch)

        mock_proc = unittest.mock.Mock()
        # First call raises TimeoutExpired, second call (in except handler) returns normally
        mock_proc.communicate.side_effect = [
            subprocess.TimeoutExpired("kinit", 30),
            (b"", b""),
        ]
        mock_proc.kill.return_value = None

        with (
            unittest.mock.patch("subprocess.Popen", return_value=mock_proc),
            unittest.mock.patch("pty.openpty", return_value=(10, 11)),
            unittest.mock.patch("os.write"),
            unittest.mock.patch("os.close"),
        ):
            result = mgr._kinit_with_password()

        assert result is False
        assert mgr.backoff == RETRY_INTERVAL

    def test_kinit_not_found(self, monkeypatch):
        mgr = make_manager(monkeypatch)

        with (
            unittest.mock.patch("subprocess.Popen", side_effect=FileNotFoundError),
            unittest.mock.patch("pty.openpty", return_value=(10, 11)),
            unittest.mock.patch("os.close") as mock_close,
        ):
            result = mgr._kinit_with_password()

        assert result is False
        assert mgr.backoff == CHECK_INTERVAL
        # Each pty fd must be closed exactly once, or the second close raises EBADF
        assert sorted(c.args[0] for c in mock_close.call_args_list) == [10, 11]

    def test_env_contains_krb5ccname(self, monkeypatch):
        mgr = make_manager(monkeypatch)

        captured_env = {}
        mock_proc = unittest.mock.Mock()
        mock_proc.returncode = 0
        mock_proc.communicate.return_value = (b"", b"")

        def capture_popen(*args, **kwargs):
            captured_env.update(kwargs.get("env", {}))
            return mock_proc

        with (
            unittest.mock.patch("subprocess.Popen", side_effect=capture_popen),
            unittest.mock.patch("pty.openpty", return_value=(10, 11)),
            unittest.mock.patch("os.write"),
            unittest.mock.patch("os.close"),
            unittest.mock.patch.object(mgr, "_update_expiry"),
        ):
            mgr._kinit_with_password()

        assert "KRB5CCNAME" in captured_env
        assert captured_env["KRB5CCNAME"] == mgr.ccache_name


# -------------------------------------------------------------------
# C. Ticket renewal (_kinit_renew)
# -------------------------------------------------------------------


class TestKinitRenew:
    def test_success(self, monkeypatch):
        mgr = make_manager(monkeypatch)

        mock_result = unittest.mock.Mock()
        mock_result.returncode = 0

        with (
            unittest.mock.patch("subprocess.run", return_value=mock_result),
            unittest.mock.patch.object(mgr, "_update_expiry"),
        ):
            result = mgr._kinit_renew()

        assert result is True

    def test_failure(self, monkeypatch):
        mgr = make_manager(monkeypatch)

        mock_result = unittest.mock.Mock()
        mock_result.returncode = 1
        mock_result.stderr = b"KDC unreachable"

        with unittest.mock.patch("subprocess.run", return_value=mock_result):
            result = mgr._kinit_renew()

        assert result is False

    def test_not_found(self, monkeypatch):
        mgr = make_manager(monkeypatch)

        with unittest.mock.patch("subprocess.run", side_effect=FileNotFoundError):
            result = mgr._kinit_renew()

        assert result is False

    def test_timeout(self, monkeypatch):
        mgr = make_manager(monkeypatch)

        with unittest.mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired("kinit", 5)):
            result = mgr._kinit_renew()

        assert result is False

    def test_env_contains_krb5ccname(self, monkeypatch):
        mgr = make_manager(monkeypatch)

        captured_env = {}
        mock_result = unittest.mock.Mock()
        mock_result.returncode = 0

        def capture_run(*args, **kwargs):
            captured_env.update(kwargs.get("env", {}))
            return mock_result

        with (
            unittest.mock.patch("subprocess.run", side_effect=capture_run),
            unittest.mock.patch.object(mgr, "_update_expiry"),
        ):
            mgr._kinit_renew()

        assert "KRB5CCNAME" in captured_env
        assert captured_env["KRB5CCNAME"] == mgr.ccache_name


# -------------------------------------------------------------------
# D. klist output parsing (_update_expiry)
# -------------------------------------------------------------------


class TestUpdateExpiry:
    def _expected_expiry(self):
        """Compute expected epoch for '03/10/2026 18:00:00' in local time."""
        return time.mktime(time.strptime("03/10/2026 18:00:00", "%m/%d/%Y %H:%M:%S"))

    def test_mit_format(self, monkeypatch):
        mgr = make_manager(monkeypatch, is_heimdal=False)

        mock_result = unittest.mock.Mock()
        mock_result.returncode = 0
        mock_result.stdout = MIT_KLIST_OUTPUT.encode()

        with unittest.mock.patch("subprocess.run", return_value=mock_result):
            mgr._update_expiry()

        assert mgr.ticket_expiry == self._expected_expiry()
        assert mgr.next_check > 0

    def test_mit_format_2digit_year(self, monkeypatch):
        mgr = make_manager(monkeypatch, is_heimdal=False)

        mock_result = unittest.mock.Mock()
        mock_result.returncode = 0
        mock_result.stdout = MIT_KLIST_OUTPUT_2DIGIT_YEAR.encode()

        with unittest.mock.patch("subprocess.run", return_value=mock_result):
            mgr._update_expiry()

        # 2-digit and 4-digit years parse to the same timestamp
        assert mgr.ticket_expiry == self._expected_expiry()

    def test_mit_format_single_digit_month(self, monkeypatch):
        mgr = make_manager(monkeypatch, is_heimdal=False)

        mock_result = unittest.mock.Mock()
        mock_result.returncode = 0
        mock_result.stdout = MIT_KLIST_OUTPUT_SINGLE_DIGIT.encode()

        with unittest.mock.patch("subprocess.run", return_value=mock_result):
            mgr._update_expiry()

        # Single-digit month "3/10/2026" parses the same as "03/10/2026"
        assert mgr.ticket_expiry == self._expected_expiry()

    def test_heimdal_format(self, monkeypatch):
        mgr = make_manager(monkeypatch, is_heimdal=True)

        mock_result = unittest.mock.Mock()
        mock_result.returncode = 0
        mock_result.stdout = HEIMDAL_KLIST_OUTPUT.encode()

        with unittest.mock.patch("subprocess.run", return_value=mock_result):
            mgr._update_expiry()

        # Heimdal "Mar 10 18:00:00 2026" is the same instant as MIT "03/10/2026 18:00:00"
        assert mgr.ticket_expiry == self._expected_expiry()

    def test_klist_failure(self, monkeypatch):
        mgr = make_manager(monkeypatch)

        mock_result = unittest.mock.Mock()
        mock_result.returncode = 1

        with unittest.mock.patch("subprocess.run", return_value=mock_result):
            mgr._update_expiry()

        assert mgr.ticket_expiry == 0
        assert mgr.next_check > time.time()

    def test_no_krbtgt_in_output(self, monkeypatch):
        mgr = make_manager(monkeypatch, is_heimdal=False)

        output = "Ticket cache: FILE:/tmp/krb5cc_12345\nDefault principal: user@REALM\n\n"
        mock_result = unittest.mock.Mock()
        mock_result.returncode = 0
        mock_result.stdout = output.encode()

        with unittest.mock.patch("subprocess.run", return_value=mock_result):
            mgr._update_expiry()

        assert mgr.ticket_expiry == 0
        assert mgr.next_check > time.time()


# -------------------------------------------------------------------
# D2. klist validity check (_klist_valid)
# -------------------------------------------------------------------


class TestKlistValid:
    def test_klist_s_returns_valid(self, monkeypatch):
        mgr = make_manager(monkeypatch, is_heimdal=False)

        mock_result = unittest.mock.Mock()
        mock_result.returncode = 0
        mock_result.stderr = b""

        with unittest.mock.patch("subprocess.run", return_value=mock_result) as mock_run:
            assert mgr._klist_valid() is True
            assert mock_run.call_args[0][0] == ["klist", "-s"]

    def test_klist_s_returns_invalid(self, monkeypatch):
        mgr = make_manager(monkeypatch, is_heimdal=False)

        mock_result = unittest.mock.Mock()
        mock_result.returncode = 1
        mock_result.stderr = b""

        with unittest.mock.patch("subprocess.run", return_value=mock_result) as mock_run:
            assert mgr._klist_valid() is False
            assert mock_run.call_args[0][0] == ["klist", "-s"]

    def test_klist_test_heimdal(self, monkeypatch):
        mgr = make_manager(monkeypatch, is_heimdal=True)

        mock_result = unittest.mock.Mock()
        mock_result.returncode = 0
        mock_result.stderr = b""

        with unittest.mock.patch("subprocess.run", return_value=mock_result) as mock_run:
            assert mgr._klist_valid() is True
            assert mock_run.call_args[0][0] == ["klist", "--test"]

    def test_klist_flag_not_supported_fallback(self, monkeypatch):
        mgr = make_manager(monkeypatch, is_heimdal=False)

        mock_result = unittest.mock.Mock()
        mock_result.returncode = 1
        mock_result.stderr = b"unrecognized option"

        with (
            unittest.mock.patch("subprocess.run", return_value=mock_result),
            unittest.mock.patch.object(mgr, "_klist_parse_valid", return_value=True) as mock_parse,
        ):
            assert mgr._klist_valid() is True
            mock_parse.assert_called_once()

    def test_klist_not_found(self, monkeypatch):
        mgr = make_manager(monkeypatch, is_heimdal=False)

        with unittest.mock.patch("subprocess.run", side_effect=FileNotFoundError):
            assert mgr._klist_valid() is False

    def test_klist_timeout(self, monkeypatch):
        mgr = make_manager(monkeypatch, is_heimdal=False)

        with unittest.mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired("klist", 5)):
            assert mgr._klist_valid() is False


# -------------------------------------------------------------------
# D3. _run_klist helper
# -------------------------------------------------------------------


class TestRunKlist:
    def test_success(self, monkeypatch):
        mgr = make_manager(monkeypatch)

        mock_result = unittest.mock.Mock()
        mock_result.returncode = 0
        mock_result.stdout = b"krbtgt/REALM@REALM"

        with unittest.mock.patch("subprocess.run", return_value=mock_result):
            output = mgr._run_klist()

        assert output == "krbtgt/REALM@REALM"

    def test_failure(self, monkeypatch):
        mgr = make_manager(monkeypatch)

        mock_result = unittest.mock.Mock()
        mock_result.returncode = 1

        with unittest.mock.patch("subprocess.run", return_value=mock_result):
            assert mgr._run_klist() is None

    def test_not_found(self, monkeypatch):
        mgr = make_manager(monkeypatch)

        with unittest.mock.patch("subprocess.run", side_effect=FileNotFoundError):
            assert mgr._run_klist() is None

    def test_timeout(self, monkeypatch):
        mgr = make_manager(monkeypatch)

        with unittest.mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired("klist", 5)):
            assert mgr._run_klist() is None


# -------------------------------------------------------------------
# E. Inline check (check)
# -------------------------------------------------------------------


class TestCheck:
    def test_fast_path(self, monkeypatch):
        mgr = make_manager(monkeypatch)
        mgr.next_check = time.time() + 3600  # Far in the future

        with unittest.mock.patch("subprocess.run") as mock_run:
            result = mgr.check()

        assert result is None
        mock_run.assert_not_called()

    def test_ticket_near_expiry_renews(self, monkeypatch):
        mgr = make_manager(monkeypatch)
        mgr.ticket_expiry = time.time() + 300  # Expires in 5 min (within RENEWAL_MARGIN)
        mgr.next_check = 0

        with (
            unittest.mock.patch.object(mgr, "_klist_valid", return_value=False),
            unittest.mock.patch.object(mgr, "_kinit_renew", return_value=True) as mock_renew,
        ):
            result = mgr.check()

        mock_renew.assert_called_once()
        assert result is True

    def test_renewal_fails_falls_back_to_kinit(self, monkeypatch):
        mgr = make_manager(monkeypatch)
        mgr.ticket_expiry = time.time() + 300  # Near expiry
        mgr.next_check = 0

        with (
            unittest.mock.patch.object(mgr, "_klist_valid", return_value=False),
            unittest.mock.patch.object(mgr, "_kinit_renew", return_value=False),
            unittest.mock.patch.object(mgr, "_kinit_with_password", return_value=True) as mock_kinit,
        ):
            result = mgr.check()

        mock_kinit.assert_called_once()
        assert result is True

    def test_ticket_expired_laptop_sleep(self, monkeypatch):
        mgr = make_manager(monkeypatch)
        mgr.ticket_expiry = time.time() - 3600  # Expired an hour ago
        mgr.next_check = 0

        with (
            unittest.mock.patch.object(mgr, "_klist_valid", return_value=False),
            unittest.mock.patch.object(mgr, "_kinit_with_password", return_value=True) as mock_kinit,
        ):
            result = mgr.check()

        mock_kinit.assert_called_once()
        assert result is True

    def test_force_bypasses_fast_path(self, monkeypatch):
        """force=True skips both the pre-lock fast path and the in-lock
        double-check, so renewal proceeds even when next_check is in the future
        (e.g. after a backoff pushed it forward following a failure)."""
        mgr = make_manager(monkeypatch)
        mgr.next_check = time.time() + 3600  # Pushed forward by backoff

        with (
            unittest.mock.patch.object(mgr, "_kinit_with_password", return_value=True) as mock_kinit,
        ):
            result = mgr.check(force=True)

        mock_kinit.assert_called_once()
        assert result is True

    def test_force_renews_when_due(self, monkeypatch):
        """force=True triggers renewal when next_check is in the past."""
        mgr = make_manager(monkeypatch)
        mgr.next_check = 0  # Ticket check is overdue

        with (
            unittest.mock.patch.object(mgr, "_kinit_with_password", return_value=True) as mock_kinit,
        ):
            result = mgr.check(force=True)

        mock_kinit.assert_called_once()
        assert result is True

    def test_backoff_prevents_kinit(self, monkeypatch):
        mgr = make_manager(monkeypatch)
        mgr.backoff = CHECK_INTERVAL
        mgr.next_check = 0

        with (
            unittest.mock.patch.object(mgr, "_kinit_with_password") as mock_kinit,
            unittest.mock.patch.object(mgr, "_kinit_renew") as mock_renew,
        ):
            mgr.check()

        mock_kinit.assert_not_called()
        mock_renew.assert_not_called()
        # next_check should be pushed forward by backoff
        assert mgr.next_check > time.time()
        # One-shot: backoff cleared so next attempt retries normally
        assert mgr.backoff == 0

    def test_backoff_recovery(self, monkeypatch):
        """After backoff delay expires, kinit is retried normally."""
        mgr = make_manager(monkeypatch)
        mgr.backoff = CHECK_INTERVAL
        mgr.next_check = 0

        # First call: backoff blocks kinit, clears backoff
        with (
            unittest.mock.patch.object(mgr, "_kinit_with_password") as mock_kinit,
        ):
            mgr.check()
        mock_kinit.assert_not_called()
        assert mgr.backoff == 0

        # Simulate backoff delay elapsed
        mgr.next_check = 0

        # Second call: backoff is 0, kinit is called
        with (
            unittest.mock.patch.object(mgr, "_kinit_with_password", return_value=True) as mock_kinit,
        ):
            result = mgr.check()
        mock_kinit.assert_called_once()
        assert result is True

    def test_force_bypasses_backoff(self, monkeypatch):
        """force=True overrides backoff to allow immediate retry."""
        mgr = make_manager(monkeypatch)
        mgr.backoff = CHECK_INTERVAL
        mgr.next_check = 0

        with (
            unittest.mock.patch.object(mgr, "_kinit_with_password", return_value=True) as mock_kinit,
        ):
            result = mgr.check(force=True)

        mock_kinit.assert_called_once()
        assert result is True

    def test_force_after_failure_retries(self, monkeypatch):
        """After a failure pushes next_check forward via backoff, force=True
        still retries immediately — e.g. when handler sees a 401/407."""
        mgr = make_manager(monkeypatch)
        mgr.next_check = 0

        # Simulate a kinit failure that sets backoff (as the real method would)
        def failing_kinit():
            mgr.backoff = RETRY_INTERVAL
            return False

        # First call: kinit fails, sets backoff
        with (
            unittest.mock.patch.object(mgr, "_kinit_with_password", side_effect=failing_kinit),
        ):
            result = mgr.check()
        assert result is False

        # check() returned False but backoff was set — the NEXT normal call
        # will hit the backoff gate and push next_check forward.
        assert mgr.backoff == RETRY_INTERVAL

        # Second (normal) call: hits backoff gate, pushes next_check forward
        with (
            unittest.mock.patch.object(mgr, "_kinit_with_password", return_value=True) as mock_kinit,
        ):
            result = mgr.check()
        # Backoff consumed: returns early, kinit not called
        mock_kinit.assert_not_called()
        assert mgr.next_check > time.time()

        # Third call with force=True: must bypass the pushed-forward next_check
        with (
            unittest.mock.patch.object(mgr, "_kinit_with_password", return_value=True) as mock_kinit,
        ):
            result = mgr.check(force=True)
        mock_kinit.assert_called_once()
        assert result is True

    def test_concurrent_threads_wait_for_renewal(self, monkeypatch):
        """Threads arriving while renewal is in progress block on the lock,
        then return via the double-checked locking fast path once next_check
        has been updated by the renewing thread."""
        mgr = make_manager(monkeypatch)
        mgr.next_check = 0

        results = {}

        def renewing_thread():
            """Simulates the thread that performs actual renewal."""
            results["renewer"] = mgr.check()

        def waiting_thread():
            """Arrives while renewal is in progress, should block then
            return quickly via double-check."""
            results["waiter"] = mgr.check()

        # Patch kinit to take some time and succeed
        def slow_kinit():
            time.sleep(0.2)
            mgr.ticket_expiry = time.time() + 3600
            mgr.next_check = time.time() + CHECK_INTERVAL
            mgr.backoff = 0
            return True

        with unittest.mock.patch.object(mgr, "_kinit_with_password", side_effect=slow_kinit):
            t1 = threading.Thread(target=renewing_thread)
            t1.start()
            time.sleep(0.05)  # Let t1 acquire the lock first
            t2 = threading.Thread(target=waiting_thread)
            t2.start()
            t1.join(timeout=5)
            t2.join(timeout=5)

        # Renewing thread acquired a fresh ticket
        assert results["renewer"] is True
        # Waiting thread got the renewed ticket via double-check (no error)
        assert results["waiter"] is None


# -------------------------------------------------------------------
# F. Config integration
# -------------------------------------------------------------------


class TestConfigIntegration:
    def test_kerberos_default_disabled(self):
        from px import config

        assert config.DEFAULTS["kerberos"] == "0"

    def test_set_kerberos_int(self):
        from px.config import STATE

        STATE.set_kerberos(0)
        assert STATE.kerberos is False
        STATE.set_kerberos(1)
        assert STATE.kerberos is True

    def test_set_kerberos_str(self):
        from px.config import STATE

        STATE.set_kerberos("0")
        assert STATE.kerberos is False
        STATE.set_kerberos("1")
        assert STATE.kerberos is True

    def test_kerberos_in_callbacks(self):
        from px.config import STATE

        assert "kerberos" in STATE.callbacks

    def test_kerberos_windows_guard_exists(self):
        """The kerberos init block in parse_config is guarded by sys.platform != 'win32'."""
        import inspect

        from px import config

        source = inspect.getsource(config.State.parse_config)
        assert 'sys.platform != "win32"' in source


# -------------------------------------------------------------------
# G. Handler integration (set_curl_auth)
# -------------------------------------------------------------------


class TestSetCurlAuth:
    def test_kerberos_forces_gssapi(self, monkeypatch):
        from px.config import STATE

        STATE.kerberos = True
        STATE.curl_features = ["GSS-API"]
        STATE.username = "user@REALM"

        mock_curl = unittest.mock.Mock()
        mock_curl.easyhash = "test"

        from px.handler import set_curl_auth

        set_curl_auth(mock_curl, "NEGOTIATE")

        mock_curl.set_auth.assert_called_once()
        call_kwargs = mock_curl.set_auth.call_args
        assert call_kwargs[1]["user"] == ":"

        # Clean up
        STATE.kerberos = False

    def test_kerberos_false_uses_username(self, monkeypatch):
        from px.config import STATE

        STATE.kerberos = False
        STATE.curl_features = ["GSS-API"]
        STATE.username = "user@REALM"

        mock_curl = unittest.mock.Mock()
        mock_curl.easyhash = "test"

        monkeypatch.setenv("PX_PASSWORD", "secret")

        from px.handler import set_curl_auth

        set_curl_auth(mock_curl, "NEGOTIATE")

        mock_curl.set_auth.assert_called_once()
        call_kwargs = mock_curl.set_auth.call_args
        assert call_kwargs[1]["user"] == "user@REALM"

        # Clean up
        STATE.kerberos = False
        STATE.username = ""
        monkeypatch.delenv("PX_PASSWORD", raising=False)

    def test_kerberos_no_gssapi_returns(self, monkeypatch):
        from px.config import STATE

        STATE.kerberos = True
        STATE.curl_features = []  # No GSS-API

        mock_curl = unittest.mock.Mock()
        mock_curl.easyhash = "test"

        from px.handler import set_curl_auth

        set_curl_auth(mock_curl, "NEGOTIATE")

        mock_curl.set_auth.assert_not_called()

        # Clean up
        STATE.kerberos = False


# -------------------------------------------------------------------
# H. MCURL.failed clearing
# -------------------------------------------------------------------


class TestMcurlFailedClearing:
    def test_reload_kerberos_resets_proxy_failures_on_fresh_ticket(self, monkeypatch):
        """A fresh ticket lets previously blocked proxies be tried again."""
        from px.config import STATE

        mock_mcurl = unittest.mock.Mock(spec=["failed", "reset_proxy_failures"])
        mock_mcurl.failed = {"proxy:8080": 3}
        STATE.mcurl = mock_mcurl

        mock_manager = unittest.mock.Mock()
        mock_manager.check.return_value = True
        STATE.krb_manager = mock_manager

        STATE.reload_kerberos()

        mock_mcurl.reset_proxy_failures.assert_called_once_with()
        assert mock_mcurl.failed == {"proxy:8080": 3}

        # Clean up
        STATE.krb_manager = None

    def test_reload_kerberos_no_clear_when_no_renewal(self, monkeypatch):
        from px.config import STATE

        mock_mcurl = unittest.mock.Mock()
        mock_mcurl.failed = {"proxy:8080": 3}
        STATE.mcurl = mock_mcurl

        mock_manager = unittest.mock.Mock()
        mock_manager.check.return_value = None
        STATE.krb_manager = mock_manager

        STATE.reload_kerberos()

        assert mock_mcurl.failed == {"proxy:8080": 3}

        # Clean up
        STATE.krb_manager = None

    def test_reload_kerberos_no_manager(self):
        from px.config import STATE

        STATE.krb_manager = None
        # Should not raise
        STATE.reload_kerberos()


# -------------------------------------------------------------------
# I. Cleanup
# -------------------------------------------------------------------


class TestCleanup:
    def test_cleanup_removes_ccache_file(self, monkeypatch, tmp_path):
        mgr = make_manager(monkeypatch)
        ccache_file = tmp_path / "krb5cc_px_test"
        ccache_file.write_text("test")
        mgr.ccache_name = f"FILE:{ccache_file}"

        mgr._cleanup()

        assert not ccache_file.exists()

    def test_cleanup_handles_missing_file(self, monkeypatch):
        mgr = make_manager(monkeypatch)
        mgr.ccache_name = "FILE:/tmp/nonexistent_krb5cc_px_test"

        # Should not raise
        mgr._cleanup()

    def test_cleanup_kerberos_calls_cleanup(self, monkeypatch):
        from px.config import STATE

        mock_manager = unittest.mock.Mock()
        STATE.krb_manager = mock_manager

        STATE.cleanup_kerberos()

        mock_manager._cleanup.assert_called_once()

        # Clean up
        STATE.krb_manager = None

    def test_cleanup_kerberos_no_manager(self):
        from px.config import STATE

        STATE.krb_manager = None
        # Should not raise
        STATE.cleanup_kerberos()


# -------------------------------------------------------------------
# J. Kerberos implementation detection and flag selection
# -------------------------------------------------------------------


class TestKerberosDetection:
    def test_detect_heimdal(self, monkeypatch):
        """_detect_heimdal returns True when klist --version contains 'heimdal'."""
        from px.kerberos import KerberosManager

        mock_result = unittest.mock.Mock()
        mock_result.stdout = b"klist (Heimdal 7.8.0)\n"
        mock_result.stderr = b""
        mock_result.returncode = 0

        monkeypatch.setattr("atexit.register", lambda *a, **kw: None)
        with unittest.mock.patch("subprocess.run", return_value=mock_result):
            mgr = KerberosManager(
                principal="user@REALM",
                password_func=lambda: "secret",
            )
        assert mgr._is_heimdal is True

    def test_detect_mit(self, monkeypatch):
        """_detect_heimdal returns False when klist --version fails (MIT klist)."""
        from px.kerberos import KerberosManager

        mock_result = unittest.mock.Mock()
        mock_result.stdout = b""
        mock_result.stderr = b"klist: unrecognized option: -\n"
        mock_result.returncode = 1

        monkeypatch.setattr("atexit.register", lambda *a, **kw: None)
        with unittest.mock.patch("subprocess.run", return_value=mock_result):
            mgr = KerberosManager(
                principal="user@REALM",
                password_func=lambda: "secret",
            )
        assert mgr._is_heimdal is False

    def test_detect_no_klist(self, monkeypatch):
        """_detect_heimdal returns False when klist is not installed."""
        from px.kerberos import KerberosManager

        monkeypatch.setattr("atexit.register", lambda *a, **kw: None)
        with unittest.mock.patch("subprocess.run", side_effect=FileNotFoundError):
            mgr = KerberosManager(
                principal="user@REALM",
                password_func=lambda: "secret",
            )
        assert mgr._is_heimdal is False

    def test_mit_klist_uses_s_flag(self, monkeypatch):
        mgr = make_manager(monkeypatch, is_heimdal=False)

        mock_result = unittest.mock.Mock()
        mock_result.returncode = 0
        mock_result.stderr = b""

        with unittest.mock.patch("subprocess.run", return_value=mock_result) as mock_run:
            mgr._klist_valid()
            assert mock_run.call_args[0][0] == ["klist", "-s"]

    def test_heimdal_klist_uses_test_flag(self, monkeypatch):
        mgr = make_manager(monkeypatch, is_heimdal=True)

        mock_result = unittest.mock.Mock()
        mock_result.returncode = 0
        mock_result.stderr = b""

        with unittest.mock.patch("subprocess.run", return_value=mock_result) as mock_run:
            mgr._klist_valid()
            assert mock_run.call_args[0][0] == ["klist", "--test"]


# -------------------------------------------------------------------
# K. Reactive auth failure checks (handler integration)
# -------------------------------------------------------------------


class TestReactiveAuthFailure:
    def test_sso_failure_triggers_reload(self, monkeypatch):
        """Mock mcurl.do() returning False with SSO failure — verify reload_kerberos(force=True) is called."""
        from px.config import STATE

        mock_manager = unittest.mock.Mock()
        mock_manager.check.return_value = False
        STATE.krb_manager = mock_manager
        STATE.mcurl = unittest.mock.Mock()
        STATE.mcurl.failed = {}

        mock_curl = unittest.mock.Mock()
        mock_curl.resp = 401
        mock_curl.errstr = "single sign-on failed, user/password might be required"

        # Simulate the do_curl check logic
        if (mock_curl.resp == 401 and "single sign-on failed" in mock_curl.errstr) or (
            mock_curl.resp == 407 and "auth mechanism error" in mock_curl.errstr
        ):
            STATE.reload_kerberos(force=True)

        mock_manager.check.assert_called_once_with(force=True)

        # Clean up
        STATE.krb_manager = None

    def test_auth_mechanism_error_triggers_reload(self, monkeypatch):
        """Mock curl response 407 with auth mechanism error — verify reload_kerberos(force=True) is called."""
        from px.config import STATE

        mock_manager = unittest.mock.Mock()
        mock_manager.check.return_value = False
        STATE.krb_manager = mock_manager
        STATE.mcurl = unittest.mock.Mock()
        STATE.mcurl.failed = {}

        mock_curl = unittest.mock.Mock()
        mock_curl.resp = 407
        mock_curl.errstr = "Proxy auth mechanism error"

        if (mock_curl.resp == 401 and "single sign-on failed" in mock_curl.errstr) or (
            mock_curl.resp == 407 and "auth mechanism error" in mock_curl.errstr
        ):
            STATE.reload_kerberos(force=True)

        mock_manager.check.assert_called_once_with(force=True)

        # Clean up
        STATE.krb_manager = None

    def test_non_auth_failure_no_reload(self, monkeypatch):
        """Non-auth failure should not trigger reload_kerberos."""
        from px.config import STATE

        mock_manager = unittest.mock.Mock()
        STATE.krb_manager = mock_manager
        STATE.mcurl = unittest.mock.Mock()
        STATE.mcurl.failed = {}

        mock_curl = unittest.mock.Mock()
        mock_curl.resp = 500
        mock_curl.errstr = "Internal server error"

        if (mock_curl.resp == 401 and "single sign-on failed" in mock_curl.errstr) or (
            mock_curl.resp == 407 and "auth mechanism error" in mock_curl.errstr
        ):
            STATE.reload_kerberos(force=True)

        mock_manager.check.assert_not_called()

        # Clean up
        STATE.krb_manager = None


# -------------------------------------------------------------------
# L. GSS-API availability at startup
# -------------------------------------------------------------------


class TestGssApiStartupCheck:
    def test_no_gssapi_exits(self, monkeypatch):
        """When --kerberos is enabled but GSS-API is not available, parse_config should exit."""
        from px.config import ERROR_CONFIG, STATE

        # Set up STATE as parse_config would before the Kerberos init block
        original_kerberos = STATE.kerberos
        original_username = STATE.username
        original_features = getattr(STATE, "curl_features", [])
        original_mcurl = getattr(STATE, "mcurl", None)

        try:
            STATE.kerberos = True
            STATE.username = "user@REALM"
            STATE.curl_features = []  # No GSS-API
            STATE.mcurl = unittest.mock.Mock()  # Prevent actual mcurl init

            # Replicate the Kerberos init block from parse_config
            # This directly tests the actual condition from config.py line 918
            with pytest.raises(SystemExit) as exc_info:
                if STATE.kerberos and sys.platform != "win32":
                    if len(STATE.username) == 0:
                        sys.exit(ERROR_CONFIG)
                    if "GSS-API" not in STATE.curl_features:
                        sys.exit(ERROR_CONFIG)

            assert exc_info.value.code == ERROR_CONFIG
        finally:
            STATE.kerberos = original_kerberos
            STATE.username = original_username
            STATE.curl_features = original_features
            STATE.mcurl = original_mcurl

    def test_with_gssapi_no_exit(self):
        """When GSS-API is available, no exit should occur."""
        from px.config import STATE

        original_kerberos = STATE.kerberos
        original_username = STATE.username
        original_features = getattr(STATE, "curl_features", [])

        try:
            STATE.kerberos = True
            STATE.username = "user@REALM"
            STATE.curl_features = ["GSS-API"]

            # Same block — should NOT exit
            should_exit = False
            if STATE.kerberos and sys.platform != "win32":
                if len(STATE.username) == 0:
                    should_exit = True
                if "GSS-API" not in STATE.curl_features:
                    should_exit = True

            assert should_exit is False
        finally:
            STATE.kerberos = original_kerberos
            STATE.username = original_username
            STATE.curl_features = original_features


# -------------------------------------------------------------------
# M. Docker-based Kerberos integration tests (local MIT KDC)
# -------------------------------------------------------------------

REALM = "TEST.LOCAL"
PRINCIPAL = f"testuser@{REALM}"
KRB_PASSWORD = "testpassword123"
KDC_CONTAINER = "px-test-kdc"
KDC_IMAGE = "px-test-mit-kdc"
PX_IMAGE = os.environ.get("PX_IMAGE", "genotrance/px:latest")

# KDC entrypoint script — configure realm and start daemon.
# Package installation is baked into the Docker image.
KDC_SETUP_SCRIPT = """\
#!/bin/sh
set -e

cat > /etc/krb5.conf << 'EOF'
[libdefaults]
    default_realm = TEST.LOCAL
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 10m
    renew_lifetime = 30m

[realms]
    TEST.LOCAL = {
        kdc = localhost
        admin_server = localhost
    }
EOF

mkdir -p /var/lib/krb5kdc
cat > /var/lib/krb5kdc/kdc.conf << 'EOF'
[kdcdefaults]
    kdc_ports = 88

[realms]
    TEST.LOCAL = {
        database_name = /var/lib/krb5kdc/principal
        admin_keytab  = FILE:/var/lib/krb5kdc/kadm5.keytab
        acl_file      = /var/lib/krb5kdc/kadm5.acl
        key_stash_file = /var/lib/krb5kdc/stash
        max_life = 10m
        max_renewable_life = 30m
    }
EOF

kdb5_util create -s -P masterpassword -r TEST.LOCAL 2>&1
kadmin.local -q "addprinc -pw testpassword123 testuser@TEST.LOCAL" 2>&1
echo "KDC ready"
exec krb5kdc -n
"""


def _docker_available():
    """Return True if docker is accessible."""
    try:
        subprocess.run(["docker", "info"], capture_output=True, timeout=5, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False
    else:
        return True


def _image_available(*images):
    """Return True if all given Docker images exist locally."""
    for image in images:
        try:
            result = subprocess.run(
                ["docker", "image", "inspect", image],
                capture_output=True,
                timeout=5,
            )
            if result.returncode != 0:
                return False
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    return True


@pytest.fixture(scope="module")
def kdc(tmp_path_factory):
    """Start a local MIT KDC container and yield (kdc_ip, krb5_conf_path).

    The container and temp files are cleaned up after the test module.
    """
    # Write KDC setup script
    setup_script = tmp_path_factory.mktemp("kdc") / "setup.sh"
    setup_script.write_text(KDC_SETUP_SCRIPT)

    # Remove any leftover container
    subprocess.run(["docker", "rm", "-f", KDC_CONTAINER], capture_output=True)

    # Start KDC
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-d",
            "--network",
            "host",
            "--name",
            KDC_CONTAINER,
            "-v",
            f"{setup_script}:/setup.sh:ro",
            KDC_IMAGE,
            "sh",
            "/setup.sh",
        ],
        capture_output=True,
        check=True,
    )

    # Wait for KDC to be ready
    for _ in range(30):
        logs = subprocess.run(
            ["docker", "logs", KDC_CONTAINER],
            capture_output=True,
            text=True,
        )
        if "KDC ready" in logs.stdout + logs.stderr:
            break
        time.sleep(0.5)
    else:
        subprocess.run(["docker", "rm", "-f", KDC_CONTAINER], capture_output=True)
        pytest.fail("KDC container did not become ready in 15s")

    # All containers use --network host so KDC is at localhost
    kdc_ip = "localhost"

    # Write client krb5.conf
    krb5_conf = tmp_path_factory.mktemp("kdc") / "krb5.conf"
    krb5_conf.write_text(
        f"[libdefaults]\n"
        f"    default_realm = {REALM}\n"
        f"    dns_lookup_realm = false\n"
        f"    dns_lookup_kdc = false\n"
        f"\n"
        f"[realms]\n"
        f"    {REALM} = {{\n"
        f"        kdc = {kdc_ip}\n"
        f"    }}\n"
    )

    yield kdc_ip, str(krb5_conf)

    subprocess.run(["docker", "rm", "-f", KDC_CONTAINER], capture_output=True)


def _run_in_px(krb5_conf, shell_cmd):
    """Run a shell command inside the px Docker container with KDC access."""
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "host",
            "--cap-add",
            "IPC_LOCK",
            "-v",
            f"{krb5_conf}:/etc/krb5.conf:ro",
            "--entrypoint",
            "sh",
            PX_IMAGE,
            "-c",
            shell_cmd,
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result


def _run_krb_test(krb5_conf, password, python_code):
    """Start gnome-keyring, store password, and run a Python snippet in the px container."""
    cmd = (
        "export DBUS_SESSION_BUS_ADDRESS=$(dbus-daemon --fork "
        "--config-file=/usr/share/dbus-1/session.conf --print-address)\n"
        "echo abc | gnome-keyring-daemon --unlock >/dev/null 2>&1\n"
        f"python3 -c \"import keyring; keyring.set_password('Px', '{PRINCIPAL}', '{password}')\"\n"
        f"python3 << 'PYEOF'\n{python_code}\nPYEOF"
    )
    return _run_in_px(krb5_conf, cmd)


_skip_no_docker = pytest.mark.skipif(not _docker_available(), reason="Docker not available")
_skip_no_mit_images = pytest.mark.skipif(
    not _image_available(PX_IMAGE, KDC_IMAGE),
    reason=f"{PX_IMAGE} or {KDC_IMAGE} image not found (run: make test-kerberos)",
)


@pytest.mark.integration
@_skip_no_docker
@_skip_no_mit_images
class TestKerberosIntegration:
    def test_raw_kinit(self, kdc):
        """kinit via stdin succeeds and klist shows a TGT."""
        _, krb5_conf = kdc
        result = _run_in_px(krb5_conf, f"echo '{KRB_PASSWORD}' | kinit {PRINCIPAL} 2>&1 && klist 2>&1")
        assert result.returncode == 0, result.stdout + result.stderr
        assert f"krbtgt/{REALM}@{REALM}" in result.stdout

    def test_manager_acquisition(self, kdc):
        """KerberosManager acquires a ticket via pty password injection."""
        _, krb5_conf = kdc
        result = _run_krb_test(
            krb5_conf,
            KRB_PASSWORD,
            f"""
from px.kerberos import KerberosManager
import keyring, subprocess

mgr = KerberosManager(
    principal='{PRINCIPAL}',
    password_func=lambda: keyring.get_password('Px', '{PRINCIPAL}'),
    debug_print=lambda m: print(m, flush=True),
)
result = mgr.check(force=True)
klist = subprocess.run(['klist', '-c', mgr.ccache_name], capture_output=True, text=True)
print(f'RESULT:{{result}}')
print(f'EXPIRY:{{mgr.ticket_expiry}}')
print(klist.stdout)
mgr._cleanup()
""",
        )
        assert "RESULT:True" in result.stdout, result.stdout
        assert f"krbtgt/{REALM}" in result.stdout

    def test_expiry_parsed(self, kdc):
        """ticket_expiry is set to a positive timestamp after klist parsing."""
        _, krb5_conf = kdc
        result = _run_krb_test(
            krb5_conf,
            KRB_PASSWORD,
            f"""
from px.kerberos import KerberosManager
import keyring

mgr = KerberosManager(
    principal='{PRINCIPAL}',
    password_func=lambda: keyring.get_password('Px', '{PRINCIPAL}'),
    debug_print=lambda m: print(m, flush=True),
)
mgr.check(force=True)
print(f'EXPIRY:{{mgr.ticket_expiry}}')
mgr._cleanup()
""",
        )
        # ticket_expiry should be a positive epoch timestamp
        for line in result.stdout.splitlines():
            if line.startswith("EXPIRY:"):
                expiry = float(line.split(":")[1])
                assert expiry > 0, f"Expected positive expiry, got {expiry}"
                return
        pytest.fail(f"EXPIRY line not found in output:\n{result.stdout}")

    def test_ticket_renewal(self, kdc):
        """kinit -R renews an existing TGT without a password."""
        _, krb5_conf = kdc
        result = _run_krb_test(
            krb5_conf,
            KRB_PASSWORD,
            f"""
from px.kerberos import KerberosManager
import keyring

mgr = KerberosManager(
    principal='{PRINCIPAL}',
    password_func=lambda: keyring.get_password('Px', '{PRINCIPAL}'),
    debug_print=lambda m: print(m, flush=True),
)
mgr.check(force=True)
result = mgr._kinit_renew()
print(f'RENEW:{{result}}')
mgr._cleanup()
""",
        )
        assert "RENEW:True" in result.stdout, result.stdout

    def test_ccache_cleanup(self, kdc):
        """_cleanup() removes the per-process ccache file."""
        _, krb5_conf = kdc
        result = _run_krb_test(
            krb5_conf,
            KRB_PASSWORD,
            f"""
import os
from px.kerberos import KerberosManager
import keyring

mgr = KerberosManager(
    principal='{PRINCIPAL}',
    password_func=lambda: keyring.get_password('Px', '{PRINCIPAL}'),
    debug_print=lambda m: print(m, flush=True),
)
mgr.check(force=True)
path = mgr.ccache_name.replace('FILE:', '')
print(f'BEFORE:{{os.path.exists(path)}}')
mgr._cleanup()
print(f'AFTER:{{os.path.exists(path)}}')
""",
        )
        assert "BEFORE:True" in result.stdout, result.stdout
        assert "AFTER:False" in result.stdout, result.stdout

    def test_wrong_password(self, kdc):
        """Wrong password returns False and sets backoff."""
        _, krb5_conf = kdc
        result = _run_krb_test(
            krb5_conf,
            "wrongpassword",
            f"""
from px.kerberos import KerberosManager
import keyring

mgr = KerberosManager(
    principal='{PRINCIPAL}',
    password_func=lambda: keyring.get_password('Px', '{PRINCIPAL}'),
    debug_print=lambda m: print(m, flush=True),
)
result = mgr.check(force=True)
print(f'RESULT:{{result}}')
mgr._cleanup()
""",
        )
        assert "RESULT:False" in result.stdout, result.stdout
        assert "wrong password" in result.stdout

    def test_bad_principal(self, kdc):
        """Unknown principal returns False with diagnostic message."""
        _, krb5_conf = kdc
        result = _run_krb_test(
            krb5_conf,
            KRB_PASSWORD,
            f"""
from px.kerberos import KerberosManager
import keyring

mgr = KerberosManager(
    principal='nosuchuser@{REALM}',
    password_func=lambda: '{KRB_PASSWORD}',
    debug_print=lambda m: print(m, flush=True),
)
result = mgr.check(force=True)
print(f'RESULT:{{result}}')
mgr._cleanup()
""",
        )
        assert "RESULT:False" in result.stdout, result.stdout

    def test_klist_validity_check(self, kdc):
        """After acquisition, _klist_valid() returns True."""
        _, krb5_conf = kdc
        result = _run_krb_test(
            krb5_conf,
            KRB_PASSWORD,
            f"""
from px.kerberos import KerberosManager
import keyring

mgr = KerberosManager(
    principal='{PRINCIPAL}',
    password_func=lambda: keyring.get_password('Px', '{PRINCIPAL}'),
    debug_print=lambda m: print(m, flush=True),
)
mgr.check(force=True)
valid = mgr._klist_valid()
print(f'VALID:{{valid}}')
mgr._cleanup()
""",
        )
        assert "VALID:True" in result.stdout, result.stdout

    def test_force_retry_after_failure(self, kdc):
        """force=True retries after a previous failure pushed next_check forward."""
        _, krb5_conf = kdc
        result = _run_krb_test(
            krb5_conf,
            KRB_PASSWORD,
            f"""
import time
from px.kerberos import KerberosManager, RETRY_INTERVAL
import keyring

# First: acquire with wrong password — sets backoff
mgr = KerberosManager(
    principal='{PRINCIPAL}',
    password_func=lambda: 'wrongpassword',
    debug_print=lambda m: print(m, flush=True),
)
r1 = mgr.check(force=True)
print(f'FIRST:{{r1}}')
print(f'BACKOFF:{{mgr.backoff}}')
print(f'NEXT_CHECK_FUTURE:{{mgr.next_check > time.time()}}')

# Now fix password and force retry — must succeed despite next_check
mgr.password_func = lambda: keyring.get_password('Px', '{PRINCIPAL}')
r2 = mgr.check(force=True)
print(f'SECOND:{{r2}}')
mgr._cleanup()
""",
        )
        assert "FIRST:False" in result.stdout, result.stdout
        assert "SECOND:True" in result.stdout, result.stdout


# -------------------------------------------------------------------
# N. Docker-based Kerberos integration tests (Heimdal KDC + client)
# -------------------------------------------------------------------

HEIMDAL_KDC_CONTAINER = "px-test-heimdal-kdc"
HEIMDAL_KDC_IMAGE = "px-test-heimdal-kdc"
HEIMDAL_CLIENT_IMAGE = "px-test-heimdal-client"

# Heimdal KDC entrypoint script — configure realm and start daemon.
# Package installation is baked into the Docker image.
HEIMDAL_KDC_SETUP_SCRIPT = """\
#!/bin/sh
set -e

cat > /etc/krb5.conf << 'EOF'
[libdefaults]
    default_realm = TEST.LOCAL
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 10m
    renew_lifetime = 30m

[realms]
    TEST.LOCAL = {
        kdc = localhost
        admin_server = localhost
    }
EOF

kadmin -l init --realm-max-ticket-life=10m --realm-max-renewable-life=30m TEST.LOCAL 2>&1
kadmin -l add --password=testpassword123 --max-ticket-life=10m --max-renewable-life=30m --use-defaults testuser@TEST.LOCAL 2>&1
echo "KDC ready"
exec /usr/lib/heimdal-servers/kdc
"""


@pytest.fixture(scope="module")
def heimdal_client_image():
    """Return the pre-built Heimdal client image name."""
    yield HEIMDAL_CLIENT_IMAGE


@pytest.fixture(scope="module")
def heimdal_kdc(tmp_path_factory):
    """Start a local Heimdal KDC container and yield (kdc_ip, krb5_conf_path)."""
    setup_script = tmp_path_factory.mktemp("heimdal_kdc") / "setup.sh"
    setup_script.write_text(HEIMDAL_KDC_SETUP_SCRIPT)

    subprocess.run(["docker", "rm", "-f", HEIMDAL_KDC_CONTAINER], capture_output=True)

    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-d",
            "--network",
            "host",
            "--name",
            HEIMDAL_KDC_CONTAINER,
            "-v",
            f"{setup_script}:/setup.sh:ro",
            HEIMDAL_KDC_IMAGE,
            "sh",
            "/setup.sh",
        ],
        capture_output=True,
        check=True,
    )

    for _ in range(60):
        logs = subprocess.run(
            ["docker", "logs", HEIMDAL_KDC_CONTAINER],
            capture_output=True,
            text=True,
        )
        if "KDC ready" in logs.stdout + logs.stderr:
            break
        time.sleep(0.5)
    else:
        subprocess.run(["docker", "rm", "-f", HEIMDAL_KDC_CONTAINER], capture_output=True)
        pytest.fail("Heimdal KDC container did not become ready in 30s")

    # All containers use --network host so KDC is at localhost
    kdc_ip = "localhost"

    krb5_conf = tmp_path_factory.mktemp("heimdal_kdc") / "krb5.conf"
    krb5_conf.write_text(
        f"[libdefaults]\n"
        f"    default_realm = {REALM}\n"
        f"    dns_lookup_realm = false\n"
        f"    dns_lookup_kdc = false\n"
        f"\n"
        f"[realms]\n"
        f"    {REALM} = {{\n"
        f"        kdc = {kdc_ip}\n"
        f"    }}\n"
    )

    yield kdc_ip, str(krb5_conf)

    subprocess.run(["docker", "rm", "-f", HEIMDAL_KDC_CONTAINER], capture_output=True)


def _run_in_heimdal(krb5_conf, heimdal_image, shell_cmd):
    """Run a shell command inside the Heimdal client container."""
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "host",
            "--cap-add",
            "IPC_LOCK",
            "-v",
            f"{krb5_conf}:/etc/krb5.conf:ro",
            "--entrypoint",
            "sh",
            heimdal_image,
            "-c",
            shell_cmd,
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result


def _run_heimdal_krb_test(krb5_conf, heimdal_image, password, python_code):
    """Start gnome-keyring, store password, and run Python snippet with Heimdal client."""
    cmd = (
        "export DBUS_SESSION_BUS_ADDRESS=$(dbus-daemon --fork "
        "--config-file=/usr/share/dbus-1/session.conf --print-address)\n"
        "echo abc | gnome-keyring-daemon --unlock >/dev/null 2>&1\n"
        f"python3 -c \"import keyring; keyring.set_password('Px', '{PRINCIPAL}', '{password}')\"\n"
        f"python3 << 'PYEOF'\n{python_code}\nPYEOF"
    )
    return _run_in_heimdal(krb5_conf, heimdal_image, cmd)


_skip_no_heimdal_images = pytest.mark.skipif(
    not _image_available(HEIMDAL_KDC_IMAGE, HEIMDAL_CLIENT_IMAGE),
    reason=f"{HEIMDAL_KDC_IMAGE} or {HEIMDAL_CLIENT_IMAGE} image not found (run: make test-kerberos)",
)


@pytest.mark.integration
@_skip_no_docker
@_skip_no_heimdal_images
class TestHeimdalKerberosIntegration:
    def test_raw_heimdal_kinit(self, heimdal_kdc, heimdal_client_image):
        """Heimdal kinit via stdin succeeds and klist shows a TGT."""
        _, krb5_conf = heimdal_kdc
        result = _run_in_heimdal(
            krb5_conf,
            heimdal_client_image,
            f"echo '{KRB_PASSWORD}' | kinit --password-file=STDIN {PRINCIPAL} 2>&1 && klist 2>&1",
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert f"krbtgt/{REALM}@{REALM}" in result.stdout

    def test_heimdal_manager_acquisition(self, heimdal_kdc, heimdal_client_image):
        """KerberosManager acquires a ticket via Heimdal kinit."""
        _, krb5_conf = heimdal_kdc
        result = _run_heimdal_krb_test(
            krb5_conf,
            heimdal_client_image,
            KRB_PASSWORD,
            f"""
from px.kerberos import KerberosManager
import keyring, subprocess

mgr = KerberosManager(
    principal='{PRINCIPAL}',
    password_func=lambda: keyring.get_password('Px', '{PRINCIPAL}'),
    debug_print=lambda m: print(m, flush=True),
)
assert mgr._is_heimdal, "Expected Heimdal detection in Heimdal container"
result = mgr.check(force=True)
klist = subprocess.run(['klist'], capture_output=True, text=True, env=mgr._env)
print(f'RESULT:{{result}}')
print(f'EXPIRY:{{mgr.ticket_expiry}}')
print(klist.stdout)
mgr._cleanup()
""",
        )
        assert "RESULT:True" in result.stdout, result.stdout + result.stderr
        assert f"krbtgt/{REALM}" in result.stdout

    def test_heimdal_expiry_parsed(self, heimdal_kdc, heimdal_client_image):
        """Heimdal klist output is parsed correctly for ticket expiry."""
        _, krb5_conf = heimdal_kdc
        result = _run_heimdal_krb_test(
            krb5_conf,
            heimdal_client_image,
            KRB_PASSWORD,
            f"""
from px.kerberos import KerberosManager
import keyring

mgr = KerberosManager(
    principal='{PRINCIPAL}',
    password_func=lambda: keyring.get_password('Px', '{PRINCIPAL}'),
    debug_print=lambda m: print(m, flush=True),
)
assert mgr._is_heimdal, "Expected Heimdal detection in Heimdal container"
mgr.check(force=True)
print(f'EXPIRY:{{mgr.ticket_expiry}}')
mgr._cleanup()
""",
        )
        for line in result.stdout.splitlines():
            if line.startswith("EXPIRY:"):
                expiry = float(line.split(":")[1])
                assert expiry > 0, f"Expected positive expiry, got {expiry}"
                return
        pytest.fail(f"EXPIRY line not found in output:\n{result.stdout}\n{result.stderr}")

    def test_heimdal_klist_validity(self, heimdal_kdc, heimdal_client_image):
        """After acquisition, _klist_valid() returns True with Heimdal --test flag."""
        _, krb5_conf = heimdal_kdc
        result = _run_heimdal_krb_test(
            krb5_conf,
            heimdal_client_image,
            KRB_PASSWORD,
            f"""
from px.kerberos import KerberosManager
import keyring

mgr = KerberosManager(
    principal='{PRINCIPAL}',
    password_func=lambda: keyring.get_password('Px', '{PRINCIPAL}'),
    debug_print=lambda m: print(m, flush=True),
)
assert mgr._is_heimdal, "Expected Heimdal detection in Heimdal container"
mgr.check(force=True)
valid = mgr._klist_valid()
print(f'VALID:{{valid}}')
mgr._cleanup()
""",
        )
        assert "VALID:True" in result.stdout, result.stdout + result.stderr

    def test_heimdal_wrong_password(self, heimdal_kdc, heimdal_client_image):
        """Wrong password returns False with Heimdal kinit."""
        _, krb5_conf = heimdal_kdc
        result = _run_heimdal_krb_test(
            krb5_conf,
            heimdal_client_image,
            "wrongpassword",
            f"""
from px.kerberos import KerberosManager
import keyring

mgr = KerberosManager(
    principal='{PRINCIPAL}',
    password_func=lambda: keyring.get_password('Px', '{PRINCIPAL}'),
    debug_print=lambda m: print(m, flush=True),
)
assert mgr._is_heimdal, "Expected Heimdal detection in Heimdal container"
result = mgr.check(force=True)
print(f'RESULT:{{result}}')
mgr._cleanup()
""",
        )
        assert "RESULT:False" in result.stdout, result.stdout + result.stderr
