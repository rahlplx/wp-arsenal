# Anti-Pattern: SFTP Channel Leak via from_transport()

## Symptom
`paramiko.SFTPClient.from_transport(transport)` called in a download loop with no `sftp.close()` — each iteration opens a new SFTP subsystem channel over the existing SSH transport. Channels accumulate until the server hits its channel limit or the transport is closed.

## Root Cause
`SFTPClient.from_transport()` bypasses the shared SFTP client managed by `WPConnection._get_sftp()`. The `_get_sftp()` method caches one SFTP session for the connection lifetime and closes it automatically when the context manager exits. `from_transport()` creates a new uncached channel every time it's called.

## Code (wrong)
```python
transport = wp._client.get_transport()
sftp = paramiko.SFTPClient.from_transport(transport)  # NEW channel each call
sftp.get(remote_path, local_path)
# sftp never closed
```

## Fix Applied
```python
sftp = wp._get_sftp()  # reuses shared channel
sftp.get(remote_path, local_path)
# closed automatically by WPConnection.__exit__
```

## How vibe-stack Should Catch It
Static check: `grep -r "SFTPClient.from_transport" scripts/` — any occurrence should be reviewed. The shared `_get_sftp()` pattern is the only correct path in this codebase.

Harness check: `grep -rn "from_transport" scripts/ --include="*.py"` must return 0 matches.

## Incident
wp-arsenal, wp-backup.py download_backup(), 2026-06-19. MEDIUM severity — hits in practice when backup has many files, leaks SSH channels per file download.
