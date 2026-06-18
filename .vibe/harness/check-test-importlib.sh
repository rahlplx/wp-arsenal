#!/usr/bin/env bash
# harness/check-test-importlib.sh
# Verifies test smoke tests use importlib, not direct import, for hyphenated scripts.
# Direct `from security import wp_scan` silently SKIPs — importlib actually runs.
set -euo pipefail

PASS=0
FAIL=0

echo "=== Harness: Test importlib Usage Check ==="

# Check for bad pattern: direct module imports of hyphenated scripts
BAD=$(grep -rn "from security import\|from management import\|from forensics import\|from hardening import\|from restoration import\|from cicd import" tests/ 2>/dev/null || true)
if [ -n "$BAD" ]; then
  echo "FAIL: Direct module import of hyphenated scripts (will silently SKIP):"
  echo "$BAD"
  FAIL=$((FAIL+1))
else
  echo "PASS: No direct module imports of hyphenated scripts"
  PASS=$((PASS+1))
fi

# Check importlib is used
IMPORTLIB=$(grep -rn "importlib.util\|spec_from_file_location" tests/ 2>/dev/null || true)
if [ -n "$IMPORTLIB" ]; then
  echo "PASS: importlib pattern found in tests"
  PASS=$((PASS+1))
else
  echo "FAIL: importlib not found in tests — import smoke tests may silently SKIP"
  FAIL=$((FAIL+1))
fi

# Count skipped vs passed (informational)
echo ""
echo "Result: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
