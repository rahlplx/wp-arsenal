#!/usr/bin/env bash
# harness/check-grep-dollar-expansion.sh
# Catches: shell $_ expansion silently breaking grep -E malware patterns.
# Regex patterns containing $_(POST|GET|REQUEST|COOKIE) get shell-expanded
# to garbage before grep sees them, making malware detection silently fail.
#
# Good: WP_PAT='...' grep -E "$WP_PAT" ...   (variable reference — safe)
# Bad:  grep -E '...$_(POST|...)...' ...       (pattern directly interpolated)
set -euo pipefail

PASS=0
FAIL=0

echo "=== Harness: Grep Dollar Expansion Check ==="

# Find grep -E calls where the pattern argument (in double quotes) contains $_
# This means the regex is being interpolated directly into the shell command
HITS=$(grep -rn 'grep.*-E.*".*\$_' scripts/ 2>/dev/null | grep -v "\.pyc" || true)

if [ -n "$HITS" ]; then
  echo "FAIL: Shell \$_ found directly in grep -E argument (will be shell-expanded):"
  echo "$HITS"
  echo ""
  echo "Fix: Pass pattern via env var: WP_PAT=\$(repr(pattern)) grep -E \"\$WP_PAT\""
  FAIL=$((FAIL+1))
else
  echo "PASS: No unguarded \$_ in grep -E string arguments"
  PASS=$((PASS+1))
fi

# Also check for the unsafe f-string pattern in Python source
PY_HITS=$(grep -rn "f\"grep.*-E.*'\\\$_" scripts/ 2>/dev/null | grep -v "\.pyc" || true)
if [ -n "$PY_HITS" ]; then
  echo "FAIL: Python f-string with \$_ in grep pattern:"
  echo "$PY_HITS"
  FAIL=$((FAIL+1))
else
  echo "PASS: No Python f-string dollar expansion in grep patterns"
  PASS=$((PASS+1))
fi

echo ""
echo "Result: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
