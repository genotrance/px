"""Tests for tests/helpers.py — credential redaction in px_print_env."""

from helpers import px_print_env


class TestPxPrintEnvRedaction:
    def test_sensitive_env_values_are_redacted(self, capsys):
        env = {"PX_PASSWORD": "s3cr3t", "PX_CLIENT_PASSWORD": "als0s3cr3t"}
        px_print_env("px --port=3128", env)
        out = capsys.readouterr().out
        assert "s3cr3t" not in out
        assert "als0s3cr3t" not in out
        assert "PX_PASSWORD=***REDACTED***" in out
        assert "PX_CLIENT_PASSWORD=***REDACTED***" in out

    def test_harmless_env_values_are_not_redacted(self, capsys):
        env = {"PX_PORT": "3128", "PX_LISTEN": "127.0.0.1"}
        px_print_env("px --port=3128", env)
        out = capsys.readouterr().out
        assert "PX_PORT=3128" in out
        assert "PX_LISTEN=127.0.0.1" in out

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
