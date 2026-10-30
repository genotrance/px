"""Tests for px.debug module — Debug singleton, pprint, dprint."""

import sys

from px.debug import Debug, dprint, missing_module_message, pprint


class TestPprint:
    def test_missing_module_message_includes_import_error(self):
        assert missing_module_message("pyspnego", ModuleNotFoundError("No module named 'cryptography'")) == (
            "Requires module pyspnego: No module named 'cryptography'"
        )

    def test_pprint_outputs_to_stdout(self, capsys):
        pprint("hello world")
        captured = capsys.readouterr()
        assert "hello world" in captured.out

    def test_pprint_multiple_args(self, capsys):
        pprint("a", "b", "c")
        captured = capsys.readouterr()
        assert "a b c" in captured.out

    def test_pprint_flushes_for_os_exit(self, monkeypatch):
        # --test ends with os._exit, which discards unflushed piped output
        flushed = []

        class Recorder:
            def write(self, _):
                pass

            def flush(self):
                flushed.append(True)

        monkeypatch.setattr(sys, "stdout", Recorder())
        pprint("result")
        assert flushed

    def test_pprint_swallows_exception(self, monkeypatch):
        # Replace stdout with something that raises on write
        class BadWriter:
            def write(self, _):
                raise OSError("broken pipe")

            def flush(self):
                pass

        monkeypatch.setattr(sys, "stdout", BadWriter())
        # Should not raise
        pprint("should not crash")


class TestDprint:
    def test_dprint_noop_when_no_debug(self):
        # Reset singleton
        old = Debug.instance
        Debug.instance = None
        try:
            # Should not raise or produce output
            dprint("no output expected")
        finally:
            Debug.instance = old

    def test_dprint_outputs_when_debug_active(self, tmp_path):
        old_instance = Debug.instance
        Debug.instance = None
        try:
            logfile = str(tmp_path / "debug.log")
            d = Debug(logfile, "w")
            dprint("test message")
            d.close()

            with open(logfile) as f:
                content = f.read()
            assert "test message" in content
        finally:
            Debug.instance = old_instance


class TestDebugClass:
    def setup_method(self):
        self._old_instance = Debug.instance
        Debug.instance = None

    def teardown_method(self):
        Debug.instance = self._old_instance

    def test_singleton(self):
        d1 = Debug()
        d2 = Debug()
        assert d1 is d2
        d1.close()

    def test_verbose_mode_redirects_stdout(self):
        """Debug() with no filename (verbose mode) must redirect sys.stdout."""
        original = sys.stdout
        d = Debug()
        try:
            assert sys.stdout is d, "sys.stdout should be the Debug instance"
            assert sys.stderr is d, "sys.stderr should be the Debug instance"
            assert d.stdout is original, "Debug.stdout should be the original stdout"
            assert d.file is None, "No file should be opened in verbose mode"
        finally:
            d.close()
        assert sys.stdout is original

    def test_write_to_file(self, tmp_path):
        logfile = str(tmp_path / "test.log")
        d = Debug(logfile, "w")
        d.write("file content")
        d.close()

        with open(logfile) as f:
            assert "file content" in f.read()

    def test_reopen(self, tmp_path):
        logfile = str(tmp_path / "reopen.log")
        d = Debug(logfile, "w")
        d.write("first")
        d.close()
        d.reopen()
        d.write("second")
        d.close()

        with open(logfile) as f:
            content = f.read()
        assert "second" in content

    def test_print_includes_call_tree(self, tmp_path):
        logfile = str(tmp_path / "tree.log")
        d = Debug(logfile, "w")
        d.print("tree test")
        d.close()

        with open(logfile) as f:
            content = f.read()
        assert "tree test" in content
        # --debug mode (file) should contain call tree with / separators
        assert "/" in content

    def test_get_print(self, tmp_path):
        logfile = str(tmp_path / "getprint.log")
        d = Debug(logfile, "w")
        printer = d.get_print()
        printer("via get_print")
        d.close()

        with open(logfile) as f:
            assert "via get_print" in f.read()
