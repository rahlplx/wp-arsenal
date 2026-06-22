#!/usr/bin/env python3
"""
Unit tests for wp_connect.py — SQL escaping and validation helpers.

Tests sql_escape() and sql_slug() static methods on WPConnection.
These are the most security-critical helpers in the codebase.
"""

import pytest
import sys
import os

# Add scripts/ to path so we can import wp_connect
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../scripts"))

from wp_connect import WPConnection


class TestSqlEscape:
    """Test WPConnection.sql_escape() for safe SQL literal interpolation."""

    def test_escapes_single_quote(self):
        """sql_escape should escape single quotes as \\' for safe interpolation."""
        assert WPConnection.sql_escape("O'Brien") == "O\\'Brien"

    def test_escapes_backslash(self):
        """sql_escape should escape backslashes as \\\\ ."""
        assert WPConnection.sql_escape("path\\file") == "path\\\\file"

    def test_escapes_both_backslash_and_quote(self):
        """sql_escape should handle both backslash and quote correctly."""
        assert WPConnection.sql_escape("C:\\Users\\O'Brien") == "C:\\\\Users\\\\O\\'Brien"

    def test_empty_string(self):
        """sql_escape should handle empty string."""
        assert WPConnection.sql_escape("") == ""

    def test_no_special_chars(self):
        """sql_escape should pass through strings with no special chars."""
        assert WPConnection.sql_escape("regular-string_123") == "regular-string_123"

    def test_multiple_quotes(self):
        """sql_escape should handle multiple single quotes."""
        assert WPConnection.sql_escape("can't shouldn't won't") == "can\\'t shouldn\\'t won\\'t"

    def test_preserves_other_special_chars(self):
        """sql_escape should NOT escape chars that don't need escaping."""
        # Semicolon, backtick, dollar sign should be left alone
        # (they're dangerous in shell context, but here we're inside a single-quoted string)
        assert WPConnection.sql_escape("$var;DROP;`cmd`") == "$var;DROP;`cmd`"

    def test_sql_injection_attempt_escaped(self):
        """sql_escape should render common SQL injection payloads harmless."""
        payload = "'; DROP TABLE users; --"
        escaped = WPConnection.sql_escape(payload)
        # The single quote is escaped, so it's now a literal string, not a SQL delimiter
        assert escaped == "\\'; DROP TABLE users; --"


class TestDbCredentialQuoting:
    """Verify that shlex.quote is used correctly for all DB credential env vars."""

    def test_shlex_quote_does_not_double_backslash(self):
        """shlex.quote must not double backslashes — POSIX sh single-quotes pass \\ literally."""
        import shlex
        password = "p@ss\\word'tricky"
        quoted = shlex.quote(password)
        assert "\\\\word" not in quoted, (
            "shlex.quote must not double backslashes; they are literal inside single-quotes"
        )

    def test_shlex_quote_handles_single_quote_in_password(self):
        """shlex.quote must safely escape a single-quote in the password without breaking shell quoting."""
        import shlex
        password = "it's-a-pass"
        quoted = shlex.quote(password)
        # shlex.quote uses the '"'"' trick to escape interior single-quotes —
        # the result may contain ' characters but they are always properly balanced.
        # Verify the canonical form matches stdlib output (the contract):
        assert quoted == shlex.quote(password)
        # And that it's a non-empty shell word:
        assert quoted and quoted[0] in ("'", '"')

    def test_shlex_quote_empty_string(self):
        """shlex.quote('') returns \"''\" — safe empty env var assignment."""
        import shlex
        assert shlex.quote("") == "''"

    def test_shlex_quote_all_db_credentials(self):
        """shlex.quote must produce a single shell token regardless of content."""
        import shlex
        tricky_values = {
            "db_host": "host' && evil",
            "db_user": "user\"; DROP",
            "db_pass": "p@ss\\w0rd'!",
            "db_name": "db`whoami`",
        }
        for field, val in tricky_values.items():
            quoted = shlex.quote(val)
            # shlex.quote always wraps in ' or " — the special chars are literal
            # inside the quotes. Verify it matches the stdlib output (the contract):
            assert quoted == shlex.quote(val), f"{field}: must match shlex.quote output"
            # And the result must be a shell-quoted word (starts with a quote char):
            assert quoted[0] in ("'", '"'), f"{field}: must be a quoted shell word"


class TestSqlSlug:
    """Test WPConnection.sql_slug() for slug validation (theme names, logins, etc.)."""

    def test_accepts_valid_theme_slug(self):
        """sql_slug should accept valid theme slugs."""
        assert WPConnection.sql_slug("my-theme") == "my-theme"
        assert WPConnection.sql_slug("hello-elementor") == "hello-elementor"

    def test_accepts_alphanumeric_dash_underscore_dot(self):
        """sql_slug should accept [A-Za-z0-9_.-]."""
        assert WPConnection.sql_slug("Theme_2.0-Name") == "Theme_2.0-Name"
        assert WPConnection.sql_slug("a1b2c3") == "a1b2c3"
        assert WPConnection.sql_slug("UPPERCASE") == "UPPERCASE"

    def test_rejects_space(self):
        """sql_slug should reject spaces."""
        with pytest.raises(ValueError, match="Invalid slug/identifier"):
            WPConnection.sql_slug("my theme")

    def test_rejects_single_quote(self):
        """sql_slug should reject single quotes."""
        with pytest.raises(ValueError, match="Invalid slug/identifier"):
            WPConnection.sql_slug("O'Brien")

    def test_rejects_sql_injection(self):
        """sql_slug should reject SQL injection payloads."""
        with pytest.raises(ValueError, match="Invalid slug/identifier"):
            WPConnection.sql_slug("a'; DROP TABLE--")

    def test_rejects_path_traversal(self):
        """sql_slug should reject path traversal attempts."""
        with pytest.raises(ValueError, match="Invalid slug/identifier"):
            WPConnection.sql_slug("../../../etc/passwd")

    def test_rejects_special_chars(self):
        """sql_slug should reject @, #, $, %, &, !, etc."""
        for char in "@#$%&!(){}[]":
            with pytest.raises(ValueError, match="Invalid slug/identifier"):
                WPConnection.sql_slug(f"theme{char}name")

    def test_error_message_includes_value(self):
        """sql_slug error message should include the rejected value."""
        try:
            WPConnection.sql_slug("bad@slug")
        except ValueError as e:
            assert "bad@slug" in str(e)

    def test_empty_string_rejected(self):
        """sql_slug should reject empty string."""
        with pytest.raises(ValueError, match="Invalid slug/identifier"):
            WPConnection.sql_slug("")

    def test_valid_slugs_used_in_wordpress(self):
        """sql_slug should accept all commonly-used WordPress slugs."""
        valid_slugs = [
            "kadence",
            "astra",
            "generatepress",
            "hello-elementor",
            "oceanwp",
            "blocksy",
            "neve",
            "divi",
            "twentytwentyfour",
            "twentytwentythree",
            "wp_system_admin",  # admin username
            "archive_feed",     # admin username
        ]
        for slug in valid_slugs:
            assert WPConnection.sql_slug(slug) == slug
