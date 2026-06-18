# Harness Report — 2026-06-19 (post-vibe-review)

**Project:** wp-arsenal (Python SSH/WordPress security toolkit)
**Commit:** e9497fe
**Tests:** 63/63 passing

---

## Results

| # | Check | Status | Notes |
|---|-------|--------|-------|
| 1 | Credential leak in source | ✅ PASS | No hardcoded passwords/tokens/keys in scripts/ |
| 2 | Shell injection (ssh f-strings) | ✅ PASS | 68 ssh(f-string) calls; `wp.*` vars are operator config (trusted); URL inputs use `shlex.quote`; forensics grep now uses `shlex.quote` |
| 3 | Credential exposure (mysqldump -p) | ✅ PASS | 0 `-p` flag uses; 4 `MYSQL_PWD=` env var uses |
| 4 | SQL input validation | ✅ PASS | False positive: `opt` from hardcoded list; `sql_escape`/`sql_slug` used at 14 boundaries |
| 5 | Error handling | ✅ PASS | No bare `except:` clauses; 23 typed except blocks |
| 6 | DB access controls | ✅ PASS | All DB access via `wp_connect.py`; no direct connectors in scripts |

## .vibe Harness Checks

| Check | Status |
|-------|--------|
| `check-credential-exposure.sh` | ✅ PASS — no mysqldump -p flag |
| `check-test-importlib.sh` | ✅ PASS — no direct hyphenated imports |
| `check-grep-dollar-expansion.sh` | ✅ PASS — no raw `$_` in grep -E args |
| `check-wp-pat-shlex.sh` | ✅ PASS — WP_PAT uses shlex.quote, not repr() |

## Result: 10/10 PASS — cleared for ship

---

## Fixes Applied This Session (vibe-review → behavioral fix loop)

| Finding | Fix | Commit |
|---------|-----|--------|
| `repr(pattern)` doubled backslashes → mangled 7+ malware regexes | `shlex.quote(pattern)` in wp-scan.py + wp-deep-audit.py | `3c12564` |
| `'{url}'` in curl → shell injection via `--site-url` | `shlex.quote(url)` in http_body/http_code | `3c12564` |
| `replace("\\","\\\\")` wrong for POSIX sh single-quotes | Reverted to quote-only escape | `3c12564` |
| REST API `isinstance` missing → AttributeError crash on dict response | `isinstance(parsed, list)` guard | `3c12564` |
| Section K no `if body` guard → false-negative on timeout | Added `if body and (...)` | `3c12564` |
| Honeypot secret raw in every page HTML/JS → any visitor reads it | HMAC-SHA256 hourly token; trap handler verifies same HMAC | `e9497fe` |
| SFTP channel leak in download_backup() loop | `wp._get_sftp()` replaces `paramiko.SFTPClient.from_transport()` | `e9497fe` |
| Evidence archive world-readable in /tmp | `chmod 700` on dir + `chmod 600` on archive | `e9497fe` |
| wp-forensics.py grep pattern unquoted | `shlex.quote(pattern)` + `WP_PAT=` env var pattern | `e9497fe` |

---

## All Issues Resolved

No open items remain from vibe-review.
