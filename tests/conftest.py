#!/usr/bin/env python3
"""
Pytest configuration and shared fixtures for wp-arsenal tests.

Provides mocked paramiko.SSHClient + SFTP for testing scripts without
a real remote server.
"""

import sys
import os
from io import BytesIO, StringIO
from unittest.mock import MagicMock, patch, Mock

import pytest

# Add scripts/ to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../scripts"))


class MockFileObject:
    """Mock file object that behaves like paramiko's stdout/stderr (returns bytes)."""

    def __init__(self, content):
        if isinstance(content, str):
            self.content = content.encode("utf-8")
        else:
            self.content = content

    def read(self):
        return self.content


@pytest.fixture
def mock_ssh_client(mocker):
    """
    Fixture: mocked paramiko.SSHClient.

    Patches paramiko.SSHClient globally so WPConnection.connect() succeeds
    without a real server. Returns the mock object so tests can configure
    return values.

    Usage:
        def test_something(mock_ssh_client):
            # Mock will return bytes from stdout/stderr
            mock_ssh_client.exec_command.return_value = (
                None,
                MockFileObject("output"),
                MockFileObject("")
            )
    """
    mock_client = MagicMock()

    # Mock the transport (needed for keepalive)
    mock_transport = MagicMock()
    mock_client.get_transport.return_value = mock_transport

    # Default exec_command returns (stdin, stdout, stderr)
    # where stdout/stderr are file-like objects that return bytes
    mock_client.exec_command.return_value = (
        None,
        MockFileObject(""),
        MockFileObject(""),
    )

    # Mock open_sftp
    mock_sftp = MagicMock()
    mock_client.open_sftp.return_value = mock_sftp

    # Patch paramiko.SSHClient globally for this test
    with patch("paramiko.SSHClient", return_value=mock_client):
        yield mock_client


@pytest.fixture
def mock_sftp(mock_ssh_client):
    """
    Fixture: mocked SFTP client (part of mock_ssh_client).

    Allows test to configure sftp_read/sftp_write responses.
    """
    return mock_ssh_client.open_sftp.return_value


@pytest.fixture
def sample_args():
    """
    Fixture: minimal argparse.Namespace for WPConnection.

    Use in tests as a starting point for WPConnection(args).
    """
    import argparse
    args = argparse.Namespace(
        host="example.com",
        user="testuser",
        password="testpass",
        port=22,
        wp_path="/var/www/html",
        db_host="localhost",
        db_user="wpuser",
        db_pass="wppass",
        db_name="wpdb",
        db_prefix="wp_",
        site_url="https://example.com",
        dry_run=False,
        quiet=True,
    )
    return args
