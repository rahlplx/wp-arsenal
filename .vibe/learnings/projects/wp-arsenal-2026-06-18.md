# Project: wp-arsenal — Session 2026-06-18

## What Was Built
Full Python/PHP WordPress security + management toolkit:
- 25 Python scripts across security, management, forensics, hardening, restoration, CI/CD
- 1 shared library (wp_connect.py) with WPConnection class
- 10 PHP MU-plugins (honeypot, rate-limiter, admin-guard, security-headers, etc.)
- 30 SKILL.md agent-instruction files
- pytest test suite: 46 tests passing, 0 skipped
- wp-theme-restore.py: 6-step full theme restoration with Web UX verification

## What Was Found (vibe-review)
- CRITICAL C1: mysqldump used `-p'...'` — DB password exposed in ps output
- CRITICAL C2: `http_code()` returns `str`, `site_responds()` compared to `int` tuple — always False
- HIGH H4: `db_pass` backslash not escaped before shell-quoting
- HIGH H6: Attacker-controlled IP passed to `whois` shell command without validation
- MEDIUM M7 (systemic): 18/20 scripts silently ignored `--config` flag — config loading bypass
- TEST: 13 of 27 tests silently SKIPPED because Python can't import hyphenated filenames

## What Was Fixed
All CRITICAL + HIGH findings fixed before ship:
- `MYSQL_PWD=` env var pattern applied to mysqldump in backup + forensics scripts
- `site_responds()`: `(200, 301, 302)` → `("200", "301", "302")`
- `db_pass`: added `.replace("\\", "\\\\")` before quote-escape
- `_whois_lookup()`: regex guard `^[\d.:a-fA-F]+$` on IP
- Config loading moved into `WPConnection.__init__()` — all 20 scripts now load config
- Tests rewritten with `importlib.util.spec_from_file_location()` — 0 skipped

## Score
- Before fixes: 6/10
- After fixes: 8/10
- Remaining open: M1 (SFTP resource leak), M5 (evidence to /tmp), L1 (honeypot secret in HTML)

## Key Learnings
- [[shared-library-config-loading]] — put mandatory setup in __init__, not helpers
- [[importlib-for-hyphenated-scripts]] — importlib needed for CLI tools with hyphens
- [[mysql-pwd-env-var]] — never use -p flag for mysql credentials over SSH
- [[credential-in-process-args]] — ps-readable credentials are CRITICAL in shared hosting
- [[str-vs-int-http-codes]] — curl output is always str; unit-test return types
- [[user-input-in-shell-command]] — DB data is attacker-controlled; validate before shell
