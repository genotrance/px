"""Tests for raise_nofile_limit() — FD soft limit raising at startup."""

import sys
import unittest.mock

import pytest


@pytest.mark.skipif(sys.platform == "win32", reason="RLIMIT_NOFILE not applicable on Windows")
class TestRaiseNofileLimit:
    def test_raises_soft_limit(self):
        """Verify that raise_nofile_limit raises the soft limit."""
        import resource

        from px.main import raise_nofile_limit

        # Save original limits
        orig_soft, orig_hard = resource.getrlimit(resource.RLIMIT_NOFILE)

        try:
            # Lower the soft limit so raise_nofile_limit has something to raise
            low_soft = 256
            if orig_hard >= low_soft:
                resource.setrlimit(resource.RLIMIT_NOFILE, (low_soft, orig_hard))
                raise_nofile_limit()
                new_soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
                assert new_soft > low_soft, f"Soft limit should have been raised from {low_soft}"
            else:
                pytest.skip(f"Hard limit {orig_hard} too low to test")
        finally:
            # Restore original limits
            resource.setrlimit(resource.RLIMIT_NOFILE, (orig_soft, orig_hard))

    def test_respects_hard_limit(self):
        """Verify that the new soft limit does not exceed the hard limit."""
        import resource

        from px.main import raise_nofile_limit

        orig_soft, orig_hard = resource.getrlimit(resource.RLIMIT_NOFILE)

        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (256, orig_hard))
            raise_nofile_limit()
            new_soft, new_hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            assert new_soft <= new_hard, "Soft limit must not exceed hard limit"
        finally:
            resource.setrlimit(resource.RLIMIT_NOFILE, (orig_soft, orig_hard))

    def test_caps_at_target(self):
        """Verify the soft limit is capped at _FD_LIMIT_TARGET."""
        import resource

        from px.main import _FD_LIMIT_TARGET, raise_nofile_limit

        orig_soft, orig_hard = resource.getrlimit(resource.RLIMIT_NOFILE)

        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (256, orig_hard))
            raise_nofile_limit()
            new_soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
            expected = min(orig_hard, _FD_LIMIT_TARGET)
            assert new_soft == expected, f"Expected {expected}, got {new_soft}"
        finally:
            resource.setrlimit(resource.RLIMIT_NOFILE, (orig_soft, orig_hard))

    def test_noop_when_already_sufficient(self):
        """Verify no-op when soft limit already meets or exceeds target."""
        import resource

        from px.main import _FD_LIMIT_TARGET, raise_nofile_limit

        orig_soft, orig_hard = resource.getrlimit(resource.RLIMIT_NOFILE)

        try:
            target = min(orig_hard, _FD_LIMIT_TARGET)
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, orig_hard))
            raise_nofile_limit()
            new_soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
            assert new_soft == target, "Limit should be unchanged"
        finally:
            resource.setrlimit(resource.RLIMIT_NOFILE, (orig_soft, orig_hard))

    def test_fallback_on_setrlimit_failure(self):
        """Verify step-down fallback when initial setrlimit fails."""
        import resource

        from px.main import raise_nofile_limit

        orig_soft, orig_hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        real_setrlimit = resource.setrlimit

        # Simulate macOS kern.maxfilesperproc rejection: only accept values <= 4096
        max_allowed = 4096
        call_count = 0

        def mock_setrlimit(res, limits):
            nonlocal call_count
            call_count += 1
            if limits[0] > max_allowed:
                raise OSError(22, "Invalid argument")
            real_setrlimit(res, limits)

        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (256, orig_hard))
            with unittest.mock.patch("resource.setrlimit", side_effect=mock_setrlimit):
                raise_nofile_limit()
            new_soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
            assert new_soft == max_allowed, f"Expected fallback to {max_allowed}, got {new_soft}"
            # Should have tried target (65536) then 8192 then 4096
            assert call_count >= 2, f"Expected multiple attempts, got {call_count}"
        finally:
            resource.setrlimit(resource.RLIMIT_NOFILE, (orig_soft, orig_hard))

    def test_warns_when_all_fallbacks_fail(self, capsys):
        """Verify warning when all fallback attempts fail."""
        import resource

        from px.main import raise_nofile_limit

        orig_soft, orig_hard = resource.getrlimit(resource.RLIMIT_NOFILE)

        # Mock setrlimit to always fail
        def always_fail(res, limits):
            raise OSError(22, "Invalid argument")

        try:
            # Set a low soft limit so the warning threshold triggers
            low_soft = 512
            if orig_hard >= low_soft:
                resource.setrlimit(resource.RLIMIT_NOFILE, (low_soft, orig_hard))
            with unittest.mock.patch("resource.setrlimit", side_effect=always_fail):
                raise_nofile_limit()
            # Soft limit should be unchanged (mock prevented any change)
            new_soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
            assert new_soft == low_soft, "Limit should be unchanged after all failures"
            captured = capsys.readouterr()
            assert "Warning" in captured.out or new_soft >= 1024
        finally:
            resource.setrlimit(resource.RLIMIT_NOFILE, (orig_soft, orig_hard))


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only test")
class TestRaiseNofileLimitWindows:
    def test_noop_on_windows(self):
        """Verify raise_nofile_limit is a no-op on Windows."""
        from px.main import raise_nofile_limit

        # Should not raise or do anything
        raise_nofile_limit()
