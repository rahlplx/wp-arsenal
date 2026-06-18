#!/usr/bin/env bash
# harness/check-syspath-consistency.sh
# Catches: scripts using "../.." sys.path instead of ".." when wp_connect.py
# lives at scripts/wp_connect.py and scripts are in scripts/subdir/.
set -euo pipefail

PASS=0
FAIL=0

echo "=== Harness: sys.path Consistency Check ==="

# Find scripts using "../.." in sys.path.insert (should be "..")
HITS=$(grep -rn 'sys.path.insert.*"\.\.\/\.\."' scripts/ 2>/dev/null \
    | grep -v "\.pyc" || true)

if [ -n "$HITS" ]; then
  echo "FAIL: Scripts using '../..' in sys.path.insert (should be '..'):"
  echo "$HITS"
  echo ""
  echo "Fix: Change '../..' to '..' in sys.path.insert()"
  FAIL=$((FAIL+1))
else
  echo "PASS: All scripts use correct '..' in sys.path.insert"
  PASS=$((PASS+1))
fi

# Verify wp_connect.py is at scripts/ level (not root)
if [ -f "scripts/wp_connect.py" ]; then
  echo "PASS: scripts/wp_connect.py exists at correct location"
  PASS=$((PASS+1))
else
  echo "FAIL: scripts/wp_connect.py not found"
  FAIL=$((FAIL+1))
fi

echo ""
echo "Result: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
