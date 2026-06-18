#!/usr/bin/env bash
# check-secret-in-html.sh
# Detect PHP constants with SECRET/KEY in name used directly in HTML output (echo, json_encode, add_query_arg).
# Any hit = raw secret exposure risk. Fix: use HMAC-derived token instead.
set -euo pipefail

SCRIPTS_DIR="${1:-scripts}"
FAIL=0

echo "--- check-secret-in-html: scanning PHP files for raw secret output ---"

# Find PHP files
PHP_FILES=$(find "$SCRIPTS_DIR" -name "*.php" 2>/dev/null)

if [ -z "$PHP_FILES" ]; then
    echo "SKIP: no PHP files found in $SCRIPTS_DIR"
    exit 0
fi

for f in $PHP_FILES; do
    # Pattern: WP_ARSENAL_*SECRET or *SECRET* or *_KEY* passed to output functions
    # Looks for: echo ..., json_encode(...SECRET...), add_query_arg('...', SECRET, ...)
    if grep -Pn "(?:echo|json_encode|add_query_arg)\s*\(?\s*[^,)]*\b(?:SECRET|_KEY)\b" "$f" 2>/dev/null; then
        echo "FAIL: possible raw secret in output: $f"
        FAIL=1
    fi
done

if [ "$FAIL" -eq 0 ]; then
    echo "PASS: no raw SECRET/KEY constants in HTML output"
    exit 0
else
    echo "FAIL: raw secret constants found in HTML output — use HMAC-derived tokens"
    exit 1
fi
