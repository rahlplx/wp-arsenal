#!/usr/bin/env bash
# harness/check-ssh-fstring-injection.sh
# Flags all f-string interpolations in .ssh() calls for manual review.
# These are potential command injection points if the interpolated value
# comes from user input or the database without validation.
set -euo pipefail

echo "=== Harness: SSH f-string Injection Audit ==="

# Find all .ssh(f"..." or .ssh(f'...' patterns
HITS=$(grep -rn "\.ssh(f[\"']" scripts/ 2>/dev/null | grep -v "\.pyc" || true)
COUNT=$(echo "$HITS" | grep -c "." || echo 0)

if [ "$COUNT" -eq 0 ]; then
  echo "PASS: No f-string interpolations in .ssh() calls"
  exit 0
fi

echo "REVIEW REQUIRED: $COUNT .ssh(f-string) calls found:"
echo "$HITS"
echo ""
echo "For each hit above, verify the interpolated variable is either:"
echo "  a) A hardcoded constant (safe)"
echo "  b) Validated with sql_slug() or regex before use (safe)"
echo "  c) Escaped with sql_escape() for string content (safe)"
echo "  d) From WPConnection attributes (host, wp_path) — typically safe"
echo ""
echo "UNSAFE: Variables sourced from database rows, user input, or HTTP responses"
echo "        without prior validation or shell-safe encoding."
echo ""
echo "Exit 0 (non-blocking) — human review required"
exit 0
