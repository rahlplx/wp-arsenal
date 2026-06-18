#!/usr/bin/env bash
# check-sftp-from-transport.sh
# Detect SFTPClient.from_transport() usage in scripts/.
# This pattern bypasses the shared _get_sftp() lifecycle management and leaks channels.
# All SFTP access must go through wp._get_sftp().
set -euo pipefail

SCRIPTS_DIR="${1:-scripts}"

echo "--- check-sftp-from-transport: scanning for raw SFTPClient.from_transport ---"

HITS=$(grep -rn "SFTPClient\.from_transport" "$SCRIPTS_DIR" --include="*.py" 2>/dev/null || true)

if [ -z "$HITS" ]; then
    echo "PASS: no SFTPClient.from_transport() usage found"
    exit 0
else
    echo "FAIL: SFTPClient.from_transport() found — use wp._get_sftp() instead:"
    echo "$HITS"
    exit 1
fi
