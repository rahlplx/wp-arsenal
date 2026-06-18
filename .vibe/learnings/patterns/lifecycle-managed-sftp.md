# Pattern: Lifecycle-Managed SFTP Client

## Problem
Code needs SFTP access to download/upload files. Using `paramiko.SFTPClient.from_transport()` creates a new SFTP channel each call, leaking channels when used in loops.

## Solution
Use the shared `_get_sftp()` method provided by `WPConnection`. It creates one SFTP session on first call, returns the cached session on subsequent calls, and closes it automatically when the context manager exits.

```python
# Wrong — new channel per call, leaks if not closed
transport = wp._client.get_transport()
sftp = paramiko.SFTPClient.from_transport(transport)
sftp.get(remote, local)

# Correct — shared, lifecycle-managed
sftp = wp._get_sftp()
sftp.get(remote, local)
# closes automatically in WPConnection.__exit__
```

## When to Use
Any time SFTP operations are needed inside a `with WPConnection(args) as wp:` block. This is always the right choice in wp-arsenal scripts.

## Implementation Reference
`wp_connect.py`: `_get_sftp()` — returns `self._sftp`, creating via `self._client.open_sftp()` on first call.

## Tested On
wp-arsenal wp-backup.py, 2026-06-19
