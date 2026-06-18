# Project Learnings — wp-arsenal — 2026-06-19

## Session Summary

**Phase:** code-review → RED-GREEN fix loop → behavioral test coverage → ship
**Starting tests:** 51 → **Final tests:** 63 (all GREEN)
**Commits:** 5 fix commits + 1 harness report + 1 behavioral GREEN commit
**Total bugs fixed:** 9 (8 from code-review + 1 bonus from vibe-review)

---

## What Went Right

### 1. TDD RED-first discipline caught ambiguous fixes
Writing `TestSecurityFixes` before implementing made 2 fixes precise — the repr() fix, the isinstance guard. Without the test, the isinstance check might have only guarded the loop (not the list check), leaving dict-response crash still possible.

### 2. vibe-review Stage 3+4 caught what code-review missed
Code-review found 8 bugs in the scripting layer. vibe-review Stage 3 (production bug hunt) and Stage 4 (OWASP) caught 4 more: honeypot secret in HTML, SFTP channel leak, world-readable /tmp archive, forensics grep unquoted. The two reviews are genuinely complementary — code-review is diff-level, vibe-review is system-level.

### 3. Multi-pass grep harness proved value
The `check-grep-dollar-expansion.sh` and `check-wp-pat-shlex.sh` harness checks confirmed the fix landed correctly in all 3 files (scan, audit, forensics) across two sessions. Without the harness, forensics grep would have stayed broken.

### 4. POSIX sh single-quote semantics lesson was sticky
The `replace("\\","\\\\")` bug reappeared in a new form (suggested as a fix, then reverted). The `posix-sh-single-quote-semantics` rule was added to evolution.json after the first incident, and the rule fired correctly in the second review to catch the suggestion before it landed in code.

---

## What Went Wrong

### 1. Behavioral test assertion wrong for shlex.quote output
`assert "' &&" not in quoted` — failed because `shlex.quote` wraps in `'...'` and escapes internal `'` as `'"'"'`, which contains `' ` as a substring. The assertion was testing the wrong thing. Correct check: verify that `shlex.quote(url)` appears verbatim in the curl cmd, and the raw unquoted url does NOT.

**Root cause:** Testing the escape sequence character-by-character rather than testing the semantic guarantee (one shell word, url appears quoted in cmd).

### 2. PowerShell heredoc syntax for git commit
`git commit -m "$(cat <<'EOF'...EOF)"` fails in PowerShell — bash syntax. Must use `git commit -m @'...'@` heredoc in PowerShell. This pattern was hit twice across the session.

### 3. Test file encoding error (UnicodeDecodeError)
`open(path)` without `encoding="utf-8"` caused UnicodeDecodeError on wp_connect.py. Windows default encoding (cp1252) fails on UTF-8 source files with non-ASCII chars. Always: `open(path, encoding="utf-8")`.

---

## New Anti-Patterns Discovered

| Name | Root Cause | Severity |
|------|-----------|----------|
| raw-secret-in-html | Constants used directly in HTML href/JS vars | HIGH |
| sftp-channel-leak | SFTPClient.from_transport() in loop without close | MEDIUM |
| world-readable-tmp | mkdir /tmp/... without chmod 700 immediately after | MEDIUM |
| posix-sh-backslash-double | replace("\\","\\\\") before single-quote escape is wrong | HIGH |
| behavioral-test-string-assert | Testing substring of escape sequence not semantic guarantee | LOW |

## New Patterns Discovered

| Name | Solution |
|------|---------|
| hmac-derived-token | hash_hmac(secret, time_slot) → safe for HTML embedding |
| lifecycle-managed-sftp | _get_sftp() not SFTPClient.from_transport() |
| chmod-immediately-after-mkdir | mkdir + chmod 700 in same ssh() call via && |

---

## Rule Evolution Events

| Rule | Event | Result |
|------|-------|--------|
| `posix-sh-single-quote-semantics` | ADDED 2026-06-19 | Caught backslash-double suggestion |
| `response-type-validation` | ADDED 2026-06-19 | Caught REST API isinstance gap |
| `user-input-shell-validation` | fires=2 → fires=3 | Caught forensics grep (missed first pass) |
| `shell-expansion-breaks-regex` | fires=2 | Clean in harness (repr→shlex fixed all) |
| NEW: `secret-derivation-for-output` | PROPOSED 2026-06-19 | Honeypot HMAC pattern |
| NEW: `resource-lifecycle-management` | PROPOSED 2026-06-19 | SFTP channel leak pattern |
| NEW: `tmp-file-permissions` | PROPOSED 2026-06-19 | /tmp chmod pattern |
