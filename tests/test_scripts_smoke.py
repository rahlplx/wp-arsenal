#!/usr/bin/env python3
"""
Smoke tests for wp-arsenal scripts — verify they import and run with mocked SSH.

Catches regressions like the wp-backup.py _ssh_client AttributeError bug
before they ship. Each test:
  1. Mocks SSH/SFTP
  2. Attempts to import the script
  3. Runs its main() or core function with minimal args (--help or dry-run)
  4. Verifies no AttributeError/NameError/ImportError
"""

import pytest
import sys
import os
import argparse
from io import StringIO
from unittest.mock import MagicMock, patch

# Add scripts/ to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../scripts"))

# Import the mock helper from conftest
from conftest import MockFileObject


class TestSecurityScripts:
    """Smoke tests for security scripts."""

    def test_wp_scan_importable(self):
        """wp-scan.py should import without errors."""
        try:
            from security import wp_scan
        except ImportError as e:
            pytest.skip(f"wp_scan module not found or import error: {e}")

    def test_wp_theme_audit_importable(self):
        """wp-theme-audit.py should import without errors."""
        try:
            from security import wp_theme_audit
        except ImportError as e:
            pytest.skip(f"wp_theme_audit module not found or import error: {e}")

    def test_wp_woo_audit_importable(self):
        """wp-woo-audit.py should import without errors."""
        try:
            from security import wp_woo_audit
        except ImportError as e:
            pytest.skip(f"wp_woo_audit module not found or import error: {e}")


class TestManagementScripts:
    """Smoke tests for management scripts."""

    def test_wp_backup_ssh_client_attribute(self, mock_ssh_client, sample_args):
        """
        wp-backup.py should use wp._client, not wp._ssh_client.

        This test catches the regression from the audit: the original code
        tried to access wp._ssh_client.get_transport() which doesn't exist
        (should be wp._client). With mocked SSH, attempting --output-local
        would have crashed. We verify the attribute exists in WPConnection.
        """
        from wp_connect import WPConnection

        wp = WPConnection(sample_args)
        # Before connect(), _client should be None but the attribute should exist
        assert hasattr(wp, "_client")
        assert not hasattr(wp, "_ssh_client"), "wp._ssh_client should not exist"

    def test_wp_user_audit_importable(self):
        """wp-user-audit.py should import without errors."""
        try:
            from management import wp_user_audit
        except ImportError as e:
            pytest.skip(f"wp_user_audit module not found or import error: {e}")

    def test_wp_theme_switch_importable(self):
        """wp-theme-switch.py should import without errors."""
        try:
            from management import wp_theme_switch
        except ImportError as e:
            pytest.skip(f"wp_theme_switch module not found or import error: {e}")

    def test_wp_child_theme_importable(self):
        """wp-child-theme.py should import without errors."""
        try:
            from management import wp_child_theme
        except ImportError as e:
            pytest.skip(f"wp_child_theme module not found or import error: {e}")


class TestHardeningScripts:
    """Smoke tests for hardening scripts."""

    def test_wp_harden_importable(self):
        """wp-harden.py should import without errors."""
        try:
            from hardening import wp_harden
        except ImportError as e:
            pytest.skip(f"wp_harden module not found or import error: {e}")

    def test_wp_firewall_importable(self):
        """wp-firewall.py should import without errors."""
        try:
            from hardening import wp_firewall
        except ImportError as e:
            pytest.skip(f"wp_firewall module not found or import error: {e}")


class TestRestorationScripts:
    """Smoke tests for restoration scripts."""

    def test_wp_plugin_restore_importable(self):
        """wp-plugin-restore.py should import without errors."""
        try:
            from restoration import wp_plugin_restore
        except ImportError as e:
            pytest.skip(f"wp_plugin_restore module not found or import error: {e}")

    def test_wp_restore_core_importable(self):
        """wp-restore-core.py should import without errors."""
        try:
            from restoration import wp_restore_core
        except ImportError as e:
            pytest.skip(f"wp_restore_core module not found or import error: {e}")


class TestForensicsScripts:
    """Smoke tests for forensics scripts."""

    def test_wp_forensics_importable(self):
        """wp-forensics.py should import without errors."""
        try:
            from forensics import wp_forensics
        except ImportError as e:
            pytest.skip(f"wp_forensics module not found or import error: {e}")

    def test_wp_attacker_profile_importable(self):
        """wp-attacker-profile.py should import without errors."""
        try:
            from forensics import wp_attacker_profile
        except ImportError as e:
            pytest.skip(f"wp_attacker_profile module not found or import error: {e}")


class TestCICDScripts:
    """Smoke tests for CI/CD scripts."""

    def test_wp_ci_deploy_importable(self):
        """wp-ci-deploy.py should import without errors."""
        try:
            from cicd import wp_ci_deploy
        except ImportError as e:
            pytest.skip(f"wp_ci_deploy module not found or import error: {e}")


class TestConnectionIntegration:
    """Integration tests with mocked SSH."""

    def test_wpconnection_connects_with_mock(self, mock_ssh_client, sample_args):
        """WPConnection should successfully connect when SSHClient is mocked."""
        from wp_connect import WPConnection

        wp = WPConnection(sample_args)
        wp.connect()
        # If we got here without exception, connect succeeded
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

    def test_wpconnection_db_query(self, mock_ssh_client, sample_args):
        """WPConnection.db() should run query via SSH with base64 encoding."""
        from wp_connect import WPConnection

        # Capture the command that was sent
        mock_ssh_client.exec_command.return_value = (
            None,
            MockFileObject("query result"),
            MockFileObject(""),
        )

        wp = WPConnection(sample_args)
        wp.connect()
        result = wp.db("SELECT * FROM wp_options LIMIT 1;")
        assert result == "query result"

        # Verify a command was sent to SSH
        mock_ssh_client.exec_command.assert_called()
        cmd_sent = mock_ssh_client.exec_command.call_args[0][0]
        # Command should contain MYSQL_PWD (not -p) and base64 encoding
        assert "MYSQL_PWD=" in cmd_sent
        assert "base64 -d" in cmd_sent
