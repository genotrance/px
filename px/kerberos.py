"Kerberos ticket lifecycle management for px"

import atexit
import contextlib
import os
import re
import subprocess
import sys
import tempfile
import threading
import time

if sys.platform != "win32":
    import fcntl
    import pty
    import termios

# How often (seconds) to re-validate via klist when the ticket is healthy
CHECK_INTERVAL = 300

# Renew this many seconds before the ticket actually expires
RENEWAL_MARGIN = 600

# Retry interval (seconds) after transient errors (kinit timeout, klist failure)
RETRY_INTERVAL = 60


class KerberosManager:
    """Manages Kerberos ticket lifecycle for px.

    Acquires tickets via kinit (password piped through pty), renews them
    proactively using the inline check pattern (like reload_proxy), and
    signals the caller to clear MCURL.failed when credentials change.

    One instance per process. Each process has its own credential cache
    in the system temp directory.
    """

    def __init__(self, principal, password_func, debug_print=None):
        """
        principal:     Kerberos principal (from --username)
        password_func: callable returning password string (from PX_PASSWORD
                       or keyring). Called on each kinit attempt so it picks
                       up any runtime changes.
        debug_print:   logging function (px's dprint)
        """
        self.principal = principal
        self.password_func = password_func
        self.dprint = debug_print or (lambda *a, **kw: None)

        self._is_heimdal = self._detect_heimdal()
        self._lock = threading.Lock()

        # Credential cache isolated per process
        ccache_path = os.path.join(tempfile.gettempdir(), f"krb5cc_px_{os.getpid()}")
        self.ccache_name = f"FILE:{ccache_path}"

        # Set for libcurl GSS-API and cache for subprocess calls
        os.environ["KRB5CCNAME"] = self.ccache_name
        self._env = os.environ.copy()

        # Timing state
        self.ticket_expiry = 0.0
        self.next_check = 0.0
        self.backoff = 0

        atexit.register(self._cleanup)

    def check(self, force=False):
        """Check ticket validity and renew if needed. Called per-request.

        Returns True if a ticket was acquired or renewed (caller should
        clear MCURL.failed), None if already valid or skipped, False if
        all renewal attempts failed.

        Fast path (O(1) timestamp compare) returns immediately when not due.
        force=True bypasses the fast path before the lock so the thread
        contends for renewal, but inside the lock the double-check still
        applies — if another thread just renewed, there is nothing to do.
        """
        now = time.time()
        if not force and now < self.next_check:
            return  # Fast path

        with self._lock:
            # Re-check under lock (double-checked locking) — if another
            # thread just renewed successfully, skip the redundant renewal.
            # force=True bypasses this so that auth failures always retry.
            if not force and now < self.next_check:
                return

            # Quick validity check via klist -s / --test
            if now < self.ticket_expiry - RENEWAL_MARGIN:
                valid = self._klist_valid()
                if valid:
                    self.next_check = min(now + CHECK_INTERVAL, self.ticket_expiry - RENEWAL_MARGIN)
                    return
                # klist says invalid — fall through to renewal

            # Rate-limit retries after failure (one-shot: clears backoff so
            # the next attempt after the delay retries normally).
            # force=True bypasses (e.g. on auth failure from handler).
            if self.backoff > 0 and not force:
                self.next_check = now + self.backoff
                self.backoff = 0
                return

            self.dprint("Kerberos: ticket renewal needed")

            # Try renewal first (cheap, no password needed)
            if now < self.ticket_expiry and self._kinit_renew():
                self.dprint("Kerberos: ticket renewed")
                return True

            # Full kinit with password
            if self._kinit_with_password():
                self.dprint("Kerberos: ticket acquired")
                return True

        return False

    def _kinit_with_password(self):
        """Acquire TGT by feeding password to kinit via a pty.

        kinit reads the password from /dev/tty (the controlling terminal),
        not from stdin.  We allocate a pty pair, make the slave side the
        child's controlling terminal via setsid + TIOCSCTTY, then write the
        password on the master side so that kinit's read(/dev/tty) sees it.
        Returns True on success, False on failure.
        Sets self.backoff on failure.
        """
        password = self.password_func()
        if password is None:
            self.dprint("Kerberos: no password available")
            return False

        ctrl_fd, child_fd = pty.openpty()

        def _child_setup():
            """preexec: new session + make pty slave the controlling tty."""
            os.setsid()
            fcntl.ioctl(child_fd, termios.TIOCSCTTY, 0)

        try:
            proc = subprocess.Popen(
                ["kinit", self.principal],
                stdin=child_fd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self._env,
                preexec_fn=_child_setup,
            )
        except FileNotFoundError:
            os.close(ctrl_fd)
            self.dprint("Kerberos: kinit not found")
            self.backoff = CHECK_INTERVAL
            return False
        finally:
            os.close(child_fd)

        with contextlib.suppress(OSError):
            os.write(ctrl_fd, password.encode() + b"\n")

        # Wait for kinit to finish before closing the master pty fd.
        # Closing ctrl_fd first would send SIGHUP to the child process.
        try:
            _, stderr = proc.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            self.dprint("Kerberos: kinit timed out")
            self.backoff = RETRY_INTERVAL
            return False
        finally:
            os.close(ctrl_fd)

        if proc.returncode != 0:
            err = stderr.decode(errors="replace").strip().lower()
            if "expired" in err or "revoked" in err:
                self.dprint(
                    "Kerberos: password expired or revoked - update via PX_PASSWORD or --password and restart px"
                )
                self.backoff = CHECK_INTERVAL
            elif "preauthentication failed" in err or "password incorrect" in err:
                self.dprint("Kerberos: wrong password - update via PX_PASSWORD or --password and restart px")
                self.backoff = CHECK_INTERVAL
            elif "not found" in err or "unknown" in err:
                self.dprint(f"Kerberos: principal {self.principal} not found")
                self.backoff = CHECK_INTERVAL
            elif "skew" in err:
                self.dprint("Kerberos: clock skew detected - check NTP configuration")
                self.backoff = CHECK_INTERVAL
            else:
                self.dprint(f"Kerberos: kinit failed: {err}")
                self.backoff = RETRY_INTERVAL
            return False

        self.backoff = 0
        # kinit does not output ticket details — klist is needed to get expiry
        self._update_expiry()
        return True

    def _kinit_renew(self):
        """Renew existing TGT via kinit -R (no password needed).
        Returns True on success, False on failure.
        """
        try:
            result = subprocess.run(
                ["kinit", "-R"],
                capture_output=True,
                timeout=5,
                env=self._env,
            )
        except FileNotFoundError:
            self.dprint("Kerberos: kinit not found for renewal")
            return False
        except subprocess.TimeoutExpired:
            self.dprint("Kerberos: kinit -R timed out")
            return False

        if result.returncode != 0:
            err = result.stderr.decode(errors="replace").strip()
            self.dprint(f"Kerberos: kinit -R failed: {err}")
            return False

        # kinit does not output ticket details — klist is needed to get expiry
        self._update_expiry()
        return True

    def _detect_heimdal(self):
        """Detect whether the installed Kerberos is Heimdal or MIT.
        Runs 'klist --version' and checks for 'heimdal' in the output.
        """
        try:
            result = subprocess.run(
                ["klist", "--version"],
                capture_output=True,
                timeout=5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
        else:
            output = (result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace")).lower()
            return "heimdal" in output

    def _klist_valid(self):
        """Quick check if the ticket cache is valid.
        Tries klist -s (MIT) or klist --test (Heimdal) first.
        Falls back to parsing klist output if the flag is not supported.
        """
        flag = "--test" if self._is_heimdal else "-s"
        try:
            result = subprocess.run(
                ["klist", flag],
                capture_output=True,
                timeout=5,
                env=self._env,
            )
        except FileNotFoundError:
            self.dprint("Kerberos: klist not found for validity check")
            return False
        except subprocess.TimeoutExpired:
            self.dprint("Kerberos: klist timed out during validity check")
            return False

        # If the flag is recognized, use the return code
        stderr = result.stderr.decode(errors="replace").lower()
        if "unrecognized" in stderr or "unknown" in stderr or "illegal" in stderr:
            self.dprint(f"Kerberos: klist {flag} not supported, falling back to parsing")
            return self._klist_parse_valid()
        return result.returncode == 0

    def _run_klist(self):
        """Run klist and return stdout, or None on failure."""
        try:
            result = subprocess.run(
                ["klist"],
                capture_output=True,
                timeout=5,
                env=self._env,
            )
        except FileNotFoundError:
            self.dprint("Kerberos: klist not found")
            return None
        except subprocess.TimeoutExpired:
            self.dprint("Kerberos: klist timed out")
            return None

        if result.returncode != 0:
            self.dprint("Kerberos: klist failed")
            return None

        return result.stdout.decode(errors="replace")

    def _klist_parse_valid(self):
        """Check ticket validity by parsing klist output (fallback)."""
        output = self._run_klist()
        if output is None:
            return False

        # If we can find a krbtgt ticket, consider it valid
        return "krbtgt" in output.lower()

    def _update_expiry(self):
        """Parse klist output to extract ticket expiry timestamp.
        Sets self.ticket_expiry and self.next_check.
        Handles MIT krb5 and Heimdal output formats.
        """
        output = self._run_klist()
        if output is None:
            self.ticket_expiry = 0.0
            self.next_check = time.time() + RETRY_INTERVAL
            return

        expiry = self._parse_expiry(output)
        if expiry is not None:
            self.ticket_expiry = expiry
            self.next_check = min(time.time() + CHECK_INTERVAL, expiry - RENEWAL_MARGIN)
        else:
            self.dprint("Kerberos: could not parse ticket expiry from klist output")
            self.ticket_expiry = 0.0
            self.next_check = time.time() + RETRY_INTERVAL

    def _parse_expiry(self, output):
        """Parse expiry timestamp from klist output.
        Returns epoch timestamp or None.
        """
        for line in output.splitlines():
            if "krbtgt" not in line.lower():
                continue

            if self._is_heimdal:
                return self._parse_heimdal_expiry(line)
            else:
                return self._parse_mit_expiry(line)

        return None

    def _parse_mit_expiry(self, line):
        """Parse MIT krb5 klist expiry format.
        Example lines:
          '03/10/2026 08:00:00  03/10/2026 18:00:00  krbtgt/REALM@REALM'
          '03/10/26 08:00:00  03/10/26 18:00:00  krbtgt/REALM@REALM'
        The expiry is the second date/time pair.
        """
        # MIT format: MM/DD/YYYY HH:MM:SS or MM/DD/YY HH:MM:SS
        pattern = r"(\d{1,2}/\d{1,2}/\d{2,4}\s+\d{2}:\d{2}:\d{2})\s+(\d{1,2}/\d{1,2}/\d{2,4}\s+\d{2}:\d{2}:\d{2})"
        match = re.search(pattern, line)
        if match:
            expiry_str = match.group(2)
            for fmt in ("%m/%d/%Y %H:%M:%S", "%m/%d/%y %H:%M:%S"):
                try:
                    t = time.strptime(expiry_str, fmt)
                    return time.mktime(t)
                except ValueError:
                    continue
        return None

    def _parse_heimdal_expiry(self, line):
        """Parse Heimdal klist expiry format.
        Example line: 'Mar 10 08:00:00 2026  Mar 10 18:00:00 2026  krbtgt/REALM@REALM'
        The expiry is the second date/time group.
        """
        # Heimdal format: Mon DD HH:MM:SS YYYY  Mon DD HH:MM:SS YYYY  principal
        pattern = (
            r"([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})"
        )
        match = re.search(pattern, line)
        if match:
            expiry_str = match.group(2)
            try:
                t = time.strptime(expiry_str, "%b %d %H:%M:%S %Y")
                return time.mktime(t)
            except ValueError:
                pass
        return None

    def _cleanup(self):
        """Remove per-process ccache file. Registered via atexit."""
        ccache_path = self.ccache_name.removeprefix("FILE:")
        with contextlib.suppress(OSError):
            os.remove(ccache_path)
