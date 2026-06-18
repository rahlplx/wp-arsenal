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
