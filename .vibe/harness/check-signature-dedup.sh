#!/usr/bin/env bash
# harness/check-signature-dedup.sh
# Catches: scripts defining their own MALWARE_PATTERNS instead of importing
# from the centralized malware_patterns.py module.
set -euo pipefail

PASS=0
FAIL=0

echo "=== Harness: Malware Signature Deduplication Check ==="

# Find MALWARE_PATTERNS definitions outside the central module
HITS=$(grep -rn "MALWARE_PATTERNS\s*=\s*\[" scripts/ 2>/dev/null \
    | grep -v "malware_patterns.py" \
    | grep -v "\.pyc" || true)

# Also check for SIGNATURES definitions (old pattern in wp-deep-audit.py)
HITS2=$(grep -rn "SIGNATURES\s*=\s*\[" scripts/ 2>/dev/null \
    | grep -v "malware_patterns.py" \
    | grep -v "\.pyc" || true)

ALL_HITS="${HITS}${HITS2}"

if [ -n "$ALL_HITS" ]; then
  echo "FAIL: Scripts defining their own malware signatures:"
  echo "$ALL_HITS"
  echo ""
  echo "Fix: Import from malware_patterns.py instead:"
  echo "  from malware_patterns import MALWARE_PATTERNS"
  FAIL=$((FAIL+1))
else
  echo "PASS: No duplicate MALWARE_PATTERNS definitions found"
  PASS=$((PASS+1))
fi

# Verify central module exists and has content
if [ -f "scripts/malware_patterns.py" ]; then
  COUNT=$(grep -c "MALWARE_PATTERNS" scripts/malware_patterns.py 2>/dev/null || echo 0)
  if [ "$COUNT" -gt 0 ]; then
    echo "PASS: scripts/malware_patterns.py exists with MALWARE_PATTERNS"
    PASS=$((PASS+1))
  else
    echo "FAIL: scripts/malware_patterns.py exists but MALWARE_PATTERNS not found"
    FAIL=$((FAIL+1))
  fi
else
  echo "FAIL: scripts/malware_patterns.py not found"
  FAIL=$((FAIL+1))
fi

echo ""
echo "Result: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
