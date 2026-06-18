# Session Telemetry — wp-arsenal — 2026-06-19

## Session Overview

| Metric | Value |
|--------|-------|
| Date | 2026-06-19 |
| Project | wp-arsenal |
| Phases | code-review → fix → harness → vibe-review → behavioral fix → learn |
| Starting commit | `2087402` (vibe telemetry) |
| Ending commit | `a0dd809` (harness report update) |
| Tests at start | 51 |
| Tests at end | 63 |
| New tests | +12 (TestSecurityFixes + TestSecurityFixesBehavioral) |
| Bugs fixed | 9 |

---

## Commit Timeline

| Commit | Message | Tests |
|--------|---------|-------|
| `3c12564` | fix(security): 5 code-review findings (shlex, POSIX sh, isinstance, body guard) | 57 |
| `0ba7997` | test(security): 6 behavioral RED tests for coverage gaps | 57 (5 RED) |
| `e9497fe` | fix(security): GREEN — honeypot HMAC, SFTP lifecycle, /tmp perms, forensics grep | 63 |
| `a0dd809` | docs(harness): updated report 63/63 all issues resolved | 63 |

---

## Code Review Findings (8 confirmed)

| # | Severity | Finding | Fixed |
|---|----------|---------|-------|
| 1 | CRITICAL | `repr(pattern)` doubled backslashes → mangled 7+ malware regexes in WP_PAT | Yes |
| 2 | CRITICAL | `repr()` with `['"]` patterns → double-quote wrapper broke bash assignment | Yes (same fix) |
| 3 | HIGH | REST API `'"slug"' in body` heuristic → dict response → `str.get()` AttributeError crash | Yes |
| 4 | HIGH | `replace("\\","\\\\")` wrong for POSIX sh single-quotes → doubled backslashes in mysqldump | Yes |
| 5 | HIGH | `'{url}'` in curl cmd → shell injection via `--site-url` single-quote | Yes |
| 6 | MEDIUM | REST API `elif rest_forbidden` branch unreachable (dead code) | Yes (restructured) |
| 7 | MEDIUM | Section K no `if body` → timeout = silent false-negative | Yes |
| 8 | LOW | `repr()` `\\x` sequences → `\\` collapsed to `\` in double-quote expansion | Yes (same fix) |

---

## Vibe-Review Additional Findings (Stage 3+4)

| # | Severity | Finding | Fixed |
|---|----------|---------|-------|
| 9 | HIGH | `honeypot.php:109` — raw WP_ARSENAL_HONEYPOT_SECRET in page HTML href + JS | Yes |
| 10 | MEDIUM | `wp-backup.py:127` — SFTPClient.from_transport() channel leak in loop | Yes |
| 11 | MEDIUM | `wp-forensics.py:51` — /tmp archive world-readable (no chmod) | Yes |
| 12 | BONUS | `wp-forensics.py:64` — grep pattern unquoted (same bug as scan/audit, missed first pass) | Yes |

---

## Grill-Me Debate Findings (not blocking, flagged for follow-up)

| # | Persona | Issue | Priority |
|---|---------|-------|----------|
| G1 | PHP-GRUMPY | `$_GET['_wpa_hp']` should be cast to string before hash_equals | LOW |
| G2 | TDD-DRILL | _get_sftp() needs behavioral call-count test, not source inspection | LOW |
| G3 | DEV | `_get_sftp()` should be renamed `get_sftp()` (public API) | LOW |
| G4 | DEV | `--evidence-dir` arg for wp-forensics.py to avoid /tmp | ENHANCEMENT |
| G5 | ATTACKER | `operator-config-trust-boundary` rule needed for future external input | RULE |

---

## Harness Results — Final (2026-06-19)

| Check | Status |
|-------|--------|
| `check-credential-exposure.sh` | ✅ PASS |
| `check-test-importlib.sh` | ✅ PASS |
| `check-grep-dollar-expansion.sh` | ✅ PASS |
| `check-ssh-fstring-injection.sh` | ✅ PASS (13 operator-config fp) |
| `check-secret-in-html.sh` | NEW (not yet run) |
| `check-sftp-from-transport.sh` | NEW (not yet run) |
| Code review: cred leak | ✅ PASS |
| Code review: shell injection | ✅ PASS |
| Code review: mysqldump | ✅ PASS |
| Code review: SQL validation | ✅ PASS |
| Code review: error handling | ✅ PASS |
| Code review: DB access | ✅ PASS |

---

## Vibe-Learn Output (2026-06-19)

### New anti-patterns
- `secret-in-html-output.md` — raw PHP constants in echo/add_query_arg
- `sftp-channel-leak.md` — SFTPClient.from_transport() bypass
- `world-readable-tmp.md` — /tmp without chmod

### New patterns
- `hmac-derived-token.md` — HMAC for safe secret-derived tokens
- `lifecycle-managed-sftp.md` — _get_sftp() shared client

### New rules (evolution.json v1.4)
- `secret-derivation-for-output` (harness: check-secret-in-html.sh)
- `resource-lifecycle-management` (harness: check-sftp-from-transport.sh)
- `tmp-file-permissions`
- `operator-config-trust-boundary`

### New harness checks
- `check-secret-in-html.sh`
- `check-sftp-from-transport.sh`

---

## Key Learnings

1. **vibe-review catches what code-review misses** — code-review is diff-level (7 of 8 in changed code), vibe-review is system-level (honeypot secret, SFTP leak, /tmp — all in code not changed by prior commits). Run both.
2. **Harness coverage ≠ codebase coverage** — `check-grep-dollar-expansion.sh` was written after fixing scan+audit but didn't scan forensics. The forensics grep bug survived one full session before vibe-review found it. Harness scripts must scan ALL scripts/, not just the ones fixed this session.
3. **Behavioral tests > source inspection** — 4 of 6 new tests are source inspection (string in source). Only 2 are behavioral. Source inspection tests break on rename; behavioral tests survive refactoring. Prefer behavioral.
4. **PowerShell heredoc is `@'...'@`** — git commit -m with multiline in PowerShell always use `@'...'@`. Bash `$(cat <<'EOF'...EOF)` does not work.
5. **shlex.quote behavioral assertion** — test the semantic guarantee (url appears quoted in cmd, raw url does not), not the escape sequence character-by-character.
