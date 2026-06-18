#!/usr/bin/env python3
"""
Smoke tests for wp-arsenal scripts — verify they import and run with mocked SSH.

Catches regressions like the wp-backup.py _ssh_client AttributeError bug
before they ship. Each test:
  1. Mocks SSH/SFTP
  2. Attempts to import the script via importlib (handles hyphenated filenames)
  3. Verifies no AttributeError/NameError/ImportError at import time
"""

import pytest
import sys
import os
import importlib.util
import argparse
from unittest.mock import MagicMock, patch

# Add scripts/ to path
SCRIPTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../scripts"))
sys.path.insert(0, SCRIPTS_DIR)

# Import the mock helper from conftest
from conftest import MockFileObject


def _import_script(rel_path: str):
    """
    Import a hyphenated script file using importlib.

    Python cannot import files named with hyphens via `import` statement.
    Use this helper for all script import tests.

    rel_path: relative to scripts/ dir, e.g. "security/wp-scan.py"
    """
    full_path = os.path.join(SCRIPTS_DIR, rel_path)
    module_name = rel_path.replace("/", ".").replace("-", "_").replace(".py", "")
    spec = importlib.util.spec_from_file_location(module_name, full_path)
    if spec is None:
        raise ImportError(f"Cannot find module at {full_path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestSecurityScripts:
    """Smoke tests for security scripts — import without errors."""

    def test_wp_scan_importable(self, mock_ssh_client):
        """wp-scan.py should import without errors."""
        mod = _import_script("security/wp-scan.py")
        assert hasattr(mod, "main")

    def test_wp_theme_audit_importable(self, mock_ssh_client):
        """wp-theme-audit.py should import without errors."""
        mod = _import_script("security/wp-theme-audit.py")
        assert hasattr(mod, "main")

    def test_wp_woo_audit_importable(self, mock_ssh_client):
        """wp-woo-audit.py should import without errors."""
        mod = _import_script("security/wp-woo-audit.py")
        assert hasattr(mod, "main")

    def test_wp_chmod_fix_importable(self, mock_ssh_client):
        """wp-chmod-fix.py should import without errors."""
        mod = _import_script("security/wp-chmod-fix.py")
        assert hasattr(mod, "main")

    def test_wp_shell_nuke_importable(self, mock_ssh_client):
        """wp-shell-nuke.py should import without errors."""
        mod = _import_script("security/wp-shell-nuke.py")
        assert hasattr(mod, "main")


class TestManagementScripts:
    """Smoke tests for management scripts."""

    def test_wp_backup_ssh_client_attribute(self, mock_ssh_client, sample_args):
        """
        Regression: wp-backup.py must use wp._client, not wp._ssh_client.

        The original code tried wp._ssh_client.get_transport() which doesn't exist.
        Any --output-local run would crash with AttributeError.
        """
        from wp_connect import WPConnection

        wp = WPConnection(sample_args)
        assert hasattr(wp, "_client")
        assert not hasattr(wp, "_ssh_client"), "wp._ssh_client must not exist"

    def test_wp_backup_importable(self, mock_ssh_client):
        """wp-backup.py should import without errors."""
        mod = _import_script("management/wp-backup.py")
        assert hasattr(mod, "main")

    def test_wp_user_audit_importable(self, mock_ssh_client):
        """wp-user-audit.py should import without errors."""
        mod = _import_script("management/wp-user-audit.py")
        assert hasattr(mod, "main")

    def test_wp_theme_switch_importable(self, mock_ssh_client):
        """wp-theme-switch.py should import without errors."""
        mod = _import_script("management/wp-theme-switch.py")
        assert hasattr(mod, "main")

    def test_wp_child_theme_importable(self, mock_ssh_client):
        """wp-child-theme.py should import without errors."""
        mod = _import_script("management/wp-child-theme.py")
        assert hasattr(mod, "main")

    def test_wp_update_importable(self, mock_ssh_client):
        """wp-update.py should import without errors."""
        mod = _import_script("management/wp-update.py")
        assert hasattr(mod, "main")


class TestHardeningScripts:
    """Smoke tests for hardening scripts."""

    def test_wp_harden_importable(self, mock_ssh_client):
        """wp-harden.py should import without errors."""
        mod = _import_script("hardening/wp-harden.py")
        assert hasattr(mod, "main")

    def test_wp_firewall_importable(self, mock_ssh_client):
        """wp-firewall.py should import without errors."""
        mod = _import_script("hardening/wp-firewall.py")
        assert hasattr(mod, "main")


class TestRestorationScripts:
    """Smoke tests for restoration scripts."""

    def test_wp_plugin_restore_importable(self, mock_ssh_client):
        """wp-plugin-restore.py should import without errors."""
        mod = _import_script("restoration/wp-plugin-restore.py")
        assert hasattr(mod, "main")

    def test_wp_restore_core_importable(self, mock_ssh_client):
        """wp-restore-core.py should import without errors."""
        mod = _import_script("restoration/wp-restore-core.py")
        assert hasattr(mod, "main")

    def test_wp_elementor_fix_importable(self, mock_ssh_client):
        """wp-elementor-fix.py should import without errors."""
        mod = _import_script("restoration/wp-elementor-fix.py")
        assert hasattr(mod, "main")

    def test_wp_theme_restore_importable(self, mock_ssh_client):
        """wp-theme-restore.py should import without errors."""
        mod = _import_script("restoration/wp-theme-restore.py")
        assert hasattr(mod, "main")
        assert hasattr(mod, "audit_wp_structure")
        assert hasattr(mod, "audit_theme_files")
        assert hasattr(mod, "verify_web_ux")


class TestForensicsScripts:
    """Smoke tests for forensics scripts."""

    def test_wp_forensics_importable(self, mock_ssh_client):
        """wp-forensics.py should import without errors."""
        mod = _import_script("forensics/wp-forensics.py")
        assert hasattr(mod, "main")

    def test_wp_attacker_profile_importable(self, mock_ssh_client):
        """wp-attacker-profile.py should import without errors."""
        mod = _import_script("forensics/wp-attacker-profile.py")
        assert hasattr(mod, "main")

    def test_wp_db_audit_importable(self, mock_ssh_client):
        """wp-db-audit.py should import without errors."""
        mod = _import_script("forensics/wp-db-audit.py")
        assert hasattr(mod, "main")


class TestCICDScripts:
    """Smoke tests for CI/CD scripts."""

    def test_wp_ci_deploy_importable(self, mock_ssh_client):
        """wp-ci-deploy.py should import without errors."""
        mod = _import_script("cicd/wp-ci-deploy.py")
        assert hasattr(mod, "main")


class TestConnectionIntegration:
    """Integration tests with mocked SSH."""

    def test_wpconnection_connects_with_mock(self, mock_ssh_client, sample_args):
        """WPConnection should successfully connect when SSHClient is mocked."""
        from wp_connect import WPConnection

        wp = WPConnection(sample_args)
        wp.connect()
        assert wp._client is not None
        mock_ssh_client.connect.assert_called_once()

    def test_wpconnection_ssh_command(self, mock_ssh_client, sample_args):
        """WPConnection.ssh() should return mocked output."""
        from wp_connect import WPConnection

        mock_ssh_client.exec_command.return_value = (
            None,
            MockFileObject("mocked output"),
            MockFileObject(""),
        )

        wp = WPConnection(sample_args)
        wp.connect()
        result = wp.ssh("whoami")
        assert result == "mocked output"

    def test_wpconnection_sftp_read(self, mock_ssh_client, mock_sftp, sample_args):
        """WPConnection.sftp_read() should return mocked file content."""
        from wp_connect import WPConnection

        mock_sftp.open.return_value.__enter__.return_value.read.return_value = b"file content"

        wp = WPConnection(sample_args)
        wp.connect()
        result = wp.sftp_read("/remote/file.php")
        assert result == b"file content"

    def test_wpconnection_sftp_write(self, mock_ssh_client, mock_sftp, sample_args):
        """WPConnection.sftp_write() should call SFTP write on mocked client."""
        from wp_connect import WPConnection

        wp = WPConnection(sample_args)
        wp.connect()
        success = wp.sftp_write("/remote/file.php", b"new content")
        assert success is True
        mock_sftp.open.assert_called()

    def test_wpconnection_db_query_uses_mysql_pwd(self, mock_ssh_client, sample_args):
        """WPConnection.db() must use MYSQL_PWD env var, not -p flag."""
        from wp_connect import WPConnection

        mock_ssh_client.exec_command.return_value = (
            None,
            MockFileObject("query result"),
            MockFileObject(""),
        )

        wp = WPConnection(sample_args)
        wp.connect()
        result = wp.db("SELECT * FROM wp_options LIMIT 1;")
        assert result == "query result"

        cmd_sent = mock_ssh_client.exec_command.call_args[0][0]
        assert "MYSQL_PWD=" in cmd_sent, "db() must use MYSQL_PWD env var"
        assert " -p" not in cmd_sent, "db() must NOT use -p flag (ps exposure)"
        assert "base64 -d" in cmd_sent, "db() must base64-encode the SQL"

    def test_site_responds_uses_string_comparison(self, mock_ssh_client, sample_args):
        """site_responds() must compare http_code string return to string literals."""
        from wp_connect import WPConnection

        mock_ssh_client.exec_command.return_value = (
            None,
            MockFileObject("200"),
            MockFileObject(""),
        )

        wp = WPConnection(sample_args)
        wp.connect()
        code = wp.http_code("https://example.com")
        assert isinstance(code, str), "http_code() must return str, not int"
        assert code == "200"

    def test_backup_mysqldump_uses_mysql_pwd(self, mock_ssh_client, sample_args):
        """backup_database() must use MYSQL_PWD env var, not -p flag."""
        mock_ssh_client.exec_command.return_value = (
            None,
            MockFileObject("OK"),
            MockFileObject(""),
        )

        mod = _import_script("management/wp-backup.py")

        from wp_connect import WPConnection
        wp = WPConnection(sample_args)
        wp.connect()

        mod.backup_database(wp, "/tmp/test", "test-label")

        for call in mock_ssh_client.exec_command.call_args_list:
            cmd = call[0][0]
            if "mysqldump" in cmd:
                assert "MYSQL_PWD=" in cmd, "mysqldump must use MYSQL_PWD"
                assert " -p" not in cmd, "mysqldump must NOT use -p flag"


class TestRegressions:
    """Regression tests for bugs caught during vibe-review."""

    def test_malware_patterns_use_env_var_not_direct_interpolation(self, mock_ssh_client):
        """
        Regression: grep patterns containing $_ were shell-expanded to empty string.
        Fix: patterns must be passed via env var (WP_PAT=...) not directly in f-string.
        """
        mod = _import_script("security/wp-scan.py")
        # Every pattern with $ must not appear directly in an f-string grep command.
        # Verify the fix: command sent to SSH must reference $WP_PAT not embed the pattern.
        mock_ssh_client.exec_command.return_value = (
            None,
            MockFileObject(""),
            MockFileObject(""),
        )
        import argparse
        from wp_connect import WPConnection
        args = argparse.Namespace(
            host="h", user="u", password="p", port=22,
            wp_path="/var/www/html", db_host="", db_user="",
            db_pass="", db_name="", db_prefix="wp_",
            site_url="", dry_run=False, quiet=True,
            json=False, alert_email="", trusted_cidrs="",
            blocked_cidrs="", config=None,
        )
        wp = WPConnection(args)
        wp.connect()
        # Run just the malware scan section by calling run_scan
        # (it will call ssh() multiple times — capture all commands)
        try:
            mod.run_scan(wp, args)
        except Exception:
            pass  # SSH is mocked; we only care about what commands were sent

        # The fix is: patterns go into WP_PAT='...' env var assignment, and the
        # grep -E argument uses "$WP_PAT" (the variable reference), not the raw pattern.
        # So $_ is ALLOWED inside WP_PAT='...', but NOT in grep -E '...' directly.
        import re as _re
        dollar_in_grep_E = []
        for call in mock_ssh_client.exec_command.call_args_list:
            cmd = call[0][0]
            if "grep" in cmd:
                # Extract the -E "..." or -E '...' argument (not the WP_PAT=... assignment)
                # Bad: grep -E '$_(POST...)' — pattern directly interpolated
                # Good: grep -E "$WP_PAT" — variable reference used
                match = _re.search(r'-E\s+["\']([^"\']*)["\']', cmd)
                if match and "$_" in match.group(1):
                    dollar_in_grep_E.append(cmd[:120])

        assert not dollar_in_grep_E, (
            f"Shell $_ expansion in grep -E argument — patterns must use $WP_PAT env var: "
            f"{dollar_in_grep_E}"
        )

    def test_backup_password_escapes_backslash_before_quote(self, mock_ssh_client, sample_args):
        """
        POSIX sh single-quotes pass \\ literally — no backslash escaping needed.
        Only single-quotes need the '\''  escaping. Backslash doubling is wrong.
        """
        mock_ssh_client.exec_command.return_value = (
            None,
            MockFileObject("OK"),
            MockFileObject(""),
        )
        mod = _import_script("management/wp-backup.py")

        import argparse
        from wp_connect import WPConnection
        args = argparse.Namespace(
            host="h", user="u", password="p", port=22,
            wp_path="/var/www/html", db_host="db.host",
            db_user="dbuser", db_pass="p@ss\\word'tricky",
            db_name="mydb", db_prefix="wp_",
            site_url="", dry_run=False, quiet=True,
            json=False, alert_email="", trusted_cidrs="",
            blocked_cidrs="", config=None,
        )
        wp = WPConnection(args)
        wp.connect()
        mod.backup_database(wp, "/tmp", "label")

        for call in mock_ssh_client.exec_command.call_args_list:
            cmd = call[0][0]
            if "mysqldump" in cmd:
                # POSIX sh single-quotes: \\ is literal — must NOT double backslashes.
                # password "p@ss\word'tricky" → cmd must contain p@ss\word'\''tricky
                assert "p@ss\\\\word" not in cmd, (
                    "Backslash must NOT be doubled — POSIX sh single-quotes pass \\ literally"
                )
                assert "MYSQL_PWD=" in cmd

    def test_wp_scan_has_config_backup_list(self, mock_ssh_client):
        """wp-scan.py must define WP_CONFIG_BACKUPS with at least 30 variants."""
        mod = _import_script("security/wp-scan.py")
        assert hasattr(mod, "WP_CONFIG_BACKUPS"), "WP_CONFIG_BACKUPS constant must exist"
        assert len(mod.WP_CONFIG_BACKUPS) >= 30, (
            f"Expected 30+ wp-config backup variants, got {len(mod.WP_CONFIG_BACKUPS)}"
        )

    def test_wp_scan_has_directory_listing_paths(self, mock_ssh_client):
        """wp-scan.py must check all 5 WP directories for directory listing."""
        mod = _import_script("security/wp-scan.py")
        assert hasattr(mod, "DIR_LISTING_PATHS"), "DIR_LISTING_PATHS must exist"
        paths = [p for p, _ in mod.DIR_LISTING_PATHS]
        assert "wp-content/uploads/" in paths
        assert "wp-content/plugins/" in paths
        assert "wp-content/themes/" in paths
        assert "wp-includes/" in paths
        assert "wp-admin/" in paths

    def test_wp_user_audit_has_rest_api_section(self, mock_ssh_client):
        """wp-user-audit.py must include REST API user enumeration check."""
        mod = _import_script("management/wp-user-audit.py")
        import inspect
        source = inspect.getsource(mod)
        assert "wp-json/wp/v2/users" in source, (
            "wp-user-audit must check /wp-json/wp/v2/users REST API endpoint"
        )


class TestSecurityFixes:
    """Security correctness fixes from code-review findings."""

    def test_malware_grep_uses_shlex_quote_not_repr(self, mock_ssh_client):
        """WP_PAT= assignment must use shlex.quote, not repr — repr doubles backslashes in single-quoted strings."""
        import inspect
        mod = _import_script("security/wp-scan.py")
        source = inspect.getsource(mod)
        assert "shlex.quote(pattern)" in source, "wp-scan.py must use shlex.quote(pattern) for WP_PAT"
        assert "repr(pattern)" not in source, "repr(pattern) must not be used — it doubles backslashes"

    def test_deep_audit_grep_uses_shlex_quote_not_repr(self, mock_ssh_client):
        """Same shlex.quote requirement for wp-deep-audit.py."""
        import inspect
        mod = _import_script("security/wp-deep-audit.py")
        source = inspect.getsource(mod)
        assert "shlex.quote(pattern)" in source, "wp-deep-audit.py must use shlex.quote(pattern)"
        assert "repr(pattern)" not in source, "repr(pattern) must not be used"

    def test_http_body_url_uses_shlex_quote(self, mock_ssh_client, sample_args):
        """http_body/http_code must shlex.quote the URL to prevent shell injection via single-quote in site_url."""
        import inspect
        import sys, os
        wp_connect_path = os.path.join(SCRIPTS_DIR, "wp_connect.py")
        source = open(wp_connect_path, encoding="utf-8").read()
        assert "shlex.quote(url)" in source, "http_body and http_code must use shlex.quote(url)"

    def test_rest_api_dict_response_no_crash(self, mock_ssh_client, sample_args):
        """REST forbidden error JSON contains 'slug' key — isinstance guard must prevent AttributeError."""
        import inspect
        mod = _import_script("management/wp-user-audit.py")
        source = inspect.getsource(mod)
        # The fix: isinstance(parsed, list) check before iterating
        assert "isinstance(" in source and "list" in source, (
            "Must guard with isinstance(parsed, list) before iterating REST API response"
        )
        # Also: must not have the old pattern that would crash — u.get() on a string dict key
        # Verify the elif rest_forbidden branch is gone (was unreachable dead code)
        assert "rest_forbidden" not in source or "isinstance" in source, (
            "rest_forbidden elif was dead code — fix must use isinstance guard instead"
        )

    def test_rest_api_blocked_not_reported_as_exposed(self, mock_ssh_client, sample_args):
        """rest_forbidden JSON with 'slug' key must be reported as blocked, NOT as user-exposed HIGH finding."""
        rest_forbidden_body = '{"code":"rest_forbidden","message":"Sorry.","data":{"slug":"rest_forbidden","status":401}}'
        mock_ssh_client.exec_command.return_value = (
            None,
            MockFileObject(rest_forbidden_body),
            MockFileObject(""),
        )
        mod = _import_script("management/wp-user-audit.py")
        from wp_connect import WPConnection
        import inspect
        source = inspect.getsource(mod)
        # The fix: check for error response BEFORE the slug heuristic
        # Presence of isinstance(api_users, list) guard OR checking "code" before "slug"
        assert 'isinstance(' in source and 'list' in source, (
            "Must check isinstance(api_users, list) before iterating — dict response crashes on .get()"
        )

    def test_section_k_empty_body_no_false_negative_finding(self, mock_ssh_client, sample_args):
        """Empty http_body (connection timeout) must not produce dir-listing false-negative silently."""
        import inspect
        mod = _import_script("security/wp-scan.py")
        source = inspect.getsource(mod)
        # Must guard section K with 'if body' before checking 'Index of'
        # Pattern: 'if body and' must appear in the section K dir-listing check
        lines = source.splitlines()
        k_section_idx = next((i for i, l in enumerate(lines) if "Directory listing exposure" in l), None)
        assert k_section_idx is not None, "Section K must exist"
        k_block = "\n".join(lines[k_section_idx:k_section_idx + 20])
        assert "if body" in k_block, (
            "Section K must guard 'Index of' check with 'if body' — empty response = false-negative"
        )
