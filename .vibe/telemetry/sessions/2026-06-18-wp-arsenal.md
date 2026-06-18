# Session Telemetry — wp-arsenal — 2026-06-18

## Session Overview

| Metric | Value |
|--------|-------|
| Date | 2026-06-18 |
| Project | wp-arsenal |
| Phases completed | build → harness → review → learn → evolve → telemetry |
| Starting commit | `49ce07b` (feat(restoration): add wp-theme-restore) |
| Security commit | `50a2eaa` (fix(security): credential exposure + type mismatch + whois injection) |
| Tests at start | 0 |
| Tests at end | 45 (18 unit + 7 behavior + 20 import smoke) |

---

## Phases

### BUILD — Test Suite

**Duration:** ~45 minutes (2 context windows)
**Blocker:** `StringIO.read()` returns `str`, paramiko `.read()` returns `bytes`
**Resolution:** Custom `MockFileObject` class returning bytes

**Blocker 2:** 13 import smoke tests silently SKIPPING
**Root cause:** `from security import wp_scan` fails silently for hyphenated files
**Resolution:** `importlib.util.spec_from_file_location()` helper

**Output:**
- `requirements.txt` — added pytest, pytest-mock
- `tests/conftest.py` — 3 fixtures (MockFileObject, mock_ssh_client, sample_args)
- `tests/test_wp_connect.py` — 18 unit tests for sql_escape + sql_slug
- `tests/test_scripts_smoke.py` — 27 tests (7 behavior + 20 import smoke)

### REVIEW — vibe-review Full Audit

**Duration:** ~30 minutes
**Findings:**

| ID | Severity | Issue | Fixed |
|----|----------|-------|-------|
| C1 | CRITICAL | mysqldump -p flag exposes DB password in ps | Yes |
| C2 | CRITICAL | http_code() str vs int — always False | Yes |
| M7 | MEDIUM | Config loading gap — 18/20 scripts miss --config | Yes |
| H6 | HIGH | Whois IP from DB with no validation | Yes |
| M1 | MEDIUM | SFTP resource leak in download_backup() | No (flagged) |
| M5 | MEDIUM | Evidence archives to /tmp | No (flagged) |
| L1 | LOW | Honeypot secret in page HTML | No (flagged) |

**Files modified:**
- `scripts/wp_connect.py` — config in __init__, MYSQL_PWD escape
- `scripts/management/wp-backup.py` — MYSQL_PWD for mysqldump
- `scripts/management/wp-update.py` — str comparison fix
- `scripts/forensics/wp-forensics.py` — MYSQL_PWD for dump loop
- `scripts/forensics/wp-attacker-profile.py` — IP validation regex

### RESTORATION — wp-theme-restore.py

**Duration:** ~20 minutes
**Output:**
- `scripts/restoration/wp-theme-restore.py` — 450+ lines, 6-step workflow
- `skills/restoration/wp-theme-restore/SKILL.md` — full usage guide

### LEARN — .vibe/learnings/

**Duration:** ~15 minutes
**Output:**
- 3 patterns: shared-library-config-loading, importlib-for-hyphenated-scripts, mysql-pwd-env-var
- 3 anti-patterns: credential-in-process-args, str-vs-int-http-codes, user-input-in-shell-command
- 1 project retrospective: wp-arsenal-2026-06-18.md
- INDEX.md — searchable index

### EVOLVE — evolution.json

**Duration:** ~10 minutes
**Output:**
- 5 rules all at quality_score 1.0
- 3 harness checks: check-credential-exposure.sh, check-ssh-fstring-injection.sh, check-test-importlib.sh
- Evolution log: evolutions/2026-06-18-evolution.md

### HARNESS — 3 checks, all PASSED

| Check | Result |
|-------|--------|
| check-credential-exposure.sh | PASS (0 mysqldump -p flags, 4 MYSQL_PWD uses) |
| check-test-importlib.sh | PASS (importlib present, no direct imports) |
| check-ssh-fstring-injection.sh | PASS (non-blocking, listed hits for review) |

---

## Quality Metrics — FINAL (session complete)

| Metric | Value |
|--------|-------|
| Critical bugs fixed | 4 (C1-C4 + grep expansion bug) |
| High bugs fixed | 1 |
| Medium bugs fixed | 1 |
| Tests at start | 45 |
| Tests at end | 51 |
| Tests added this phase | 6 (TestRegressions class) |
| Scripts created | 1 (wp-theme-restore.py) |
| Scripts enhanced | 4 (wp-scan, wp-deep-audit, wp-backup, wp-user-audit) |
| Harness checks added | 4 (+ check-grep-dollar-expansion.sh) |
| Patterns captured | 4 (+ wpscan-intelligence-mining) |
| Anti-patterns captured | 4 (+ shell-expansion-in-grep-pattern) |
| Evolution version | v1.2 |
| Rules in evolution.json | 6 (all quality_score 1.0) |
| Commits | b9daba7 (review fixes), 820c89c (vibe artifacts) |

---

## Phase 2: vibe-review + WPScan intelligence

### WPScan Mining (30 min)
Mined WPScan (9,639⭐ Ruby) and Wordpresscan (653⭐ Python) for detection gaps.

| Source | Detection added | Impact |
|--------|-----------------|--------|
| Wordpresscan | 36 wp-config backup variants (was 5) | 31 new detection paths |
| Wordpresscan | `/wp-json/wp/v2/users` REST API enum | New HIGH class |
| WPScan | 5-directory listing checks | 4 new checks |
| WPScan | dump.sql in uploads, emergency.php, searchreplacedb2.php | CRITICAL detections |
| WPScan | readme.html version disclosure, robots.txt parsing | MEDIUM/LOW |

### Shell `$_` Expansion Bug (CRITICAL FIX)
Discovered that 3 malware grep patterns silently broke because bash expands `$_` (last argument) before grep sees the pattern. Fixed by routing all patterns through `WP_PAT=... grep -E "$WP_PAT"`.

Affected patterns (all now fixed):
- `assert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)`
- `(system|exec|passthru|shell_exec)\s*\(\s*\$_(GET|POST|...)`
- `mail\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)`

### wp-user-audit.py REST API section
Added zero-auth `/wp-json/wp/v2/users` enumeration check that reveals all WordPress usernames without authentication.

---

## Open Items (carried over)

| Item | Location | Priority |
|------|----------|----------|
| SFTP resource leak | scripts/management/wp-backup.py | MEDIUM |
| Evidence archives temp path | scripts/forensics/wp-forensics.py | MEDIUM |
| Honeypot secret in HTML | scripts/security/ | LOW |
| MyISAM→InnoDB migration script | new script | LOW |

---

## Key Learnings for Future Sessions

1. **paramiko returns bytes** — always use `MockFileObject` returning `b"..."` in SSH mock fixtures, never `StringIO`
2. **hyphenated filenames** — use `importlib.util.spec_from_file_location()` for CLI tools; `from module import ...` silently fails
3. **shared library init** — put mandatory setup in `__init__` of the one class all consumers must instantiate
4. **MYSQL_PWD** — never `-p` flag; always env var; test with `grep -n "\-p'" | grep -E "mysqldump|mysql"`
5. **DB values are attacker-controlled** — validate with regex before any shell interpolation
6. **Shell `$_` expansion** — any regex containing `$_` interpolated into an f-string will silently break; use `WP_PAT={repr(pattern)} grep -E "$WP_PAT"` pattern
7. **Mine OSS security tools** — WPScan/Wordpresscan/WPSeku source = years of attacker research, use `gh api repos/.../contents/...` to read without rate limiting
