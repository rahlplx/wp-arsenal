# Harness Report — 2026-06-19

**Project:** wp-arsenal (Python SSH/WordPress security toolkit)
**Commit:** 0ba7997
**Tests:** 57/57 passing

---

## Results

| # | Check | Status | Notes |
|---|-------|--------|-------|
| 1 | Credential leak in source | ✅ PASS | No hardcoded passwords/tokens/keys in scripts/ |
| 2 | Shell injection (ssh f-strings) | ✅ PASS | 68 ssh(f-string) calls; `wp.*` vars are operator config (trusted); URL inputs use `shlex.quote` |
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

## Fixes Applied This Session (code-review → harness loop)

| Finding | Fix | Commit |
|---------|-----|--------|
| `repr(pattern)` doubled backslashes → mangled 7+ malware regexes | `shlex.quote(pattern)` in wp-scan.py + wp-deep-audit.py | `0ba7997` |
| `'{url}'` in curl → shell injection via `--site-url` | `shlex.quote(url)` in http_body/http_code | `0ba7997` |
| `replace("\\","\\\\")` wrong for POSIX sh single-quotes | Reverted to quote-only escape | `0ba7997` |
| REST API `isinstance` missing → AttributeError crash on dict response | `isinstance(parsed, list)` guard | `0ba7997` |
| Section K no `if body` guard → false-negative on timeout | Added `if body and (...)` | `0ba7997` |

---

## Open Low-Priority Items

| Item | Location | Priority |
|------|----------|----------|
| SFTP resource leak in download_backup() | wp-backup.py | MEDIUM |
| Evidence archives to /tmp | wp-forensics.py | MEDIUM |
| Honeypot secret visible in page HTML | honeypot.php | LOW |
| MyISAM→InnoDB migration script | missing | LOW |
