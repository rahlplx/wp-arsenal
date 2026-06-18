#!/usr/bin/env bash
# harness/check-credential-exposure.sh
# Catches CRITICAL: DB credentials in process arguments (visible via ps)
# Fires on: any mysqldump/mysql call using -p flag in SSH command strings
set -euo pipefail

PASS=0
FAIL=0
WARN=0

echo "=== Harness: Credential Exposure Check ==="

# 1. Grep for -p'...' pattern in python files
HITS=$(grep -rn "\-p'" scripts/ 2>/dev/null | grep -E "mysqldump|mysql" || true)
if [ -n "$HITS" ]; then
  echo "FAIL: DB password passed via -p flag (visible in ps output):"
  echo "$HITS"
  FAIL=$((FAIL+1))
else
  echo "PASS: No mysqldump/mysql -p flag found"
  PASS=$((PASS+1))
fi

# 2. Check that all db() calls use MYSQL_PWD
MYSQL_PWD_USES=$(grep -rn "MYSQL_PWD" scripts/ 2>/dev/null | grep -v "\.pyc" || true)
if [ -n "$MYSQL_PWD_USES" ]; then
  echo "PASS: MYSQL_PWD env var pattern found ($( echo "$MYSQL_PWD_USES" | wc -l | tr -d ' ') uses)"
  PASS=$((PASS+1))
else
  echo "WARN: No MYSQL_PWD usage found — is DB password handling correct?"
  WARN=$((WARN+1))
fi

echo ""
echo "Result: $PASS passed, $FAIL failed, $WARN warnings"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
