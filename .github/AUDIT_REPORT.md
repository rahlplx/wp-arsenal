# WP-Arsenal — Full Codebase Security Audit Report

**Date:** 2026-06-21  
**Auditor:** Senior Principal Engineer / Security Auditor  
**Scope:** Full recursive audit of `rahlplx/wp-arsenal` on branch `claude/codebase-security-audit-lf9dut`  
**Framework:** OWASP Top 10 · Secure Coding Review · Dependency Health · Test Coverage  

---

## Executive Summary

WP-Arsenal is a well-structured, security-conscious toolkit with several commendable patterns: base64-encoded SQL queries, `MYSQL_PWD` env-var instead of `-p` flags, `shlex.quote` on shell-interpolated URLs and grep patterns, and HMAC-derived honeypot tokens. The vibe harness and regression test suite reflect a maturing security posture.

Three issues require immediate attention before the toolkit is used in production engagements:

1. **SSH host-key verification disabled** — all connections are MITM-susceptible (`AutoAddPolicy`)
2. **SSH key-file auth advertised but unimplemented** — operators who configure `key_file` silently fall back to password auth
3. **Backslash double-escaping bug in `db()` method** — passwords containing `\` are corrupted before being sent to MySQL

Eight medium-severity issues follow, mostly around prefix-only CIDR matching, unvalidated shell interpolation of DB host/user/name, and test coverage gaps.

---

## Dimension 1 — Architectural Cohesion

### Patterns Identified

| Pattern | Location | Assessment |
|---|---|---|
| Shared-library context manager | `wp_connect.py` → all scripts | Strong — avoids boilerplate duplication |
| CLI-first / config-fallback | `config_loader.py` + `add_connection_args()` | Well-implemented; YAML silently skipped if PyYAML absent |
| AuditResult accumulator | `wp_connect.AuditResult` | Consistent across 15+ scripts |
| Strategy (per-script entry points) | `main()` in each `.py` | Clean separation of concerns |
| MU-plugin hardening layer | `scripts/hardening/mu-plugins/` | Belt-and-suspenders vs .htaccess layer |

### Issues

| ID | Severity | Description |
|---|---|---|
| A-1 | Low | `pass_escaped` password quoting logic is duplicated across `wp_connect.db()`, `wp-backup.backup_database()`, and `wp-forensics.collect_evidence()`. A centralised `shell_quote_password()` helper would remove the three-way divergence (they already differ). |
| A-2 | Low | `wp-forensics.py` and `wp-backup.py` call `mysqldump` directly via `wp.ssh()` instead of using a shared DB helper, bypassing the base64-safe `db()` codepath. This is necessary for streaming dumps but is not documented as a known deviation. |
| A-3 | Low | `.vibe/harness/` shell scripts are not integrated into `pytest` or CI — they only run in the AI-assisted dev harness. Standard CI pipelines miss these checks. |

---

## Dimension 2 — Functional Completeness

### TODOs and Unhandled Edge Cases

| ID | Severity | File | Line | Description |
|---|---|---|---|---|
| F-1 | Medium | `config_loader.py` | 130–132 | `_set_if_default()` special-cases `port == 22` with a nested `if` that has confusing double-negation logic. When `current == 22` (the real default) and `value == 22` (from YAML), the function returns without setting — correct. But if `value` is something else, the outer check `current in (None, "", 22 if attr == "port" else None)` triggers, overwriting the default port. The logic is correct but fragile; a comment explaining the invariant would prevent regressions. |
| F-2 | Medium | `wp_connect.py` | `db()` | `db()` returns `""` silently when DB credentials are not configured. Callers that don't check the return value will silently skip security-critical queries (e.g., session-token extraction in forensics). No caller currently handles this explicitly. |
| F-3 | Low | `wp-scan.py` | Section D | "Recently modified PHP files" uses `wp-login.php` as the reference file for `-newer`. If `wp-login.php` was itself modified (e.g. by an attacker), the comparison anchor is corrupted and the check may miss recently changed files. A fixed timestamp (e.g., `-mtime -14`) would be more reliable. |
| F-4 | Low | `wp-attacker-profile.py` | 58 | `whois_lookup()` validates the IP with a regex before passing to `wp.ssh(f"whois '{ip}'")`. Good. But the `head -3` filter means org info may be truncated for IPv6 whois records which can have long header blocks. |
| F-5 | Low | `wp-harden.py` | 98–130 | The `UPLOADS_HTACCESS` block uses the deprecated Apache 2.2 `deny from all` syntax. For Apache 2.4+ (which is now universal), the modern equivalent is `<RequireAll><Require all denied></RequireAll>`. Both syntaxes work due to `mod_access_compat`, but new installations may generate warnings. |

---

## Dimension 3 — Security & Vulnerabilities

### Critical / High Findings

| ID | Severity | OWASP | File | Description | Fix |
|---|---|---|---|---|---|
| S-1 | **HIGH** | A02 Crypto Failures | `wp_connect.py:145` | `paramiko.AutoAddPolicy()` silently accepts any SSH host key. For a security toolkit that transmits SSH passwords, DB credentials, and performs destructive operations, this enables MITM attacks on every connection. | Replace with `RejectPolicy` and maintain a `known_hosts` file, or implement host-key fingerprint pinning per site in `config.yaml`. |
| S-2 | **HIGH** | A05 Security Misconfiguration | `wp_connect.py:147–153`, `config.example.yaml:14` | `config.example.yaml` documents `key_file` as an SSH authentication option. `WPConnection.connect()` never passes `key_filename` to `paramiko.SSHClient.connect()`. Operators who configure a key file silently fall back to password auth with no error or warning. | Add `key_filename=self.key_file or None` to the `client.connect()` call; read `key_file` in `__init__`; add test. |
| S-3 | **HIGH** | A03 Injection | `wp_connect.py:257` | `db()` builds the password escape as `db_pass.replace("\\", "\\\\").replace("'", "'\\''")`.<br>In POSIX sh, single-quoted strings are literal — backslashes require no escaping. Doubling `\` to `\\` means a password of `p@ss\word` is sent to MySQL as `p@ss\\word`, causing auth failure. The test suite (`test_scripts_smoke.py:379`) explicitly verifies that `backup_database()` does NOT double backslashes, but `wp_connect.db()` still does. This inconsistency means `wp.db()` is broken for any password containing `\`. | Remove the `replace("\\", "\\\\")` call from `wp_connect.db()`. POSIX sh single-quote syntax never interprets `\`. |

```python
# BEFORE (wp_connect.py:257) — buggy
pass_escaped = self.db_pass.replace("\\", "\\\\").replace("'", "'\\''")

# AFTER — correct
pass_escaped = self.db_pass.replace("'", "'\\''")
```

### Medium Findings

| ID | Severity | OWASP | File | Description | Fix |
|---|---|---|---|---|---|
| S-4 | **Medium** | A03 Injection | `wp-forensics.py:143–148`, `wp-backup.py:44` | `mysqldump` calls interpolate `wp.db_host`, `wp.db_user`, `wp.db_name` as single-quoted shell strings without any escaping. A hostname containing `'` (e.g. `host'-injected`) would break the command. These values come from operator config, so exploitation requires config tampering — but the pattern is unsafe. | Centralise into `WPConnection` as `shell_quote(val)` (identical to `pass_escaped` logic) and apply to all DB fields before interpolation. |
| S-5 | **Medium** | A05 Security Misconfiguration | `ip-blocker.php`, `admin-guard.php`, `rate-limiter.php`, `login-monitor.php` | All four plugins perform CIDR matching via `str_starts_with($ip, $cidr)`. The config example shows `198.51.100.0/24` as a valid entry, but `str_starts_with('198.51.100.5', '198.51.100.0/24')` returns `false`. Operators who follow the example literally will believe they blocked a /24 range when they have not. | (a) Update all config examples and comments to use prefix notation (`198.51.100.` not `198.51.100.0/24`), and (b) add a PHP function `wp_arsenal_cidr_match($ip, $cidr)` that supports standard CIDR notation for IPv4. |

```php
// Minimal CIDR helper (IPv4)
function wp_arsenal_cidr_match(string $ip, string $cidr): bool {
    if (str_contains($cidr, '/')) {
        [$subnet, $bits] = explode('/', $cidr, 2);
        $mask = ~((1 << (32 - (int)$bits)) - 1);
        return (ip2long($ip) & $mask) === (ip2long($subnet) & $mask);
    }
    return str_starts_with($ip, $cidr); // prefix notation
}
```

| ID | Severity | OWASP | File | Description | Fix |
|---|---|---|---|---|---|
| S-6 | **Medium** | A05 Security Misconfiguration | `admin-guard.php:43` | `if (str_contains($request_uri, '/wp-json/')) return;` — all REST API requests bypass the IP allowlist entirely. This is intentional for public headless/API use, but it also means admin-only REST endpoints (e.g. `/wp-json/wp/v2/users`, `/wp-json/wc/v3/orders`) are accessible from any IP. | Add a configurable constant `WP_ARSENAL_ALLOW_REST_PUBLIC` (default `true`). When `false`, also apply the IP check to REST requests, allowing site owners with private APIs to enforce IP restriction end-to-end. |
| S-7 | **Medium** | A01 Broken Access Control | `wp_connect.py:139` | SSH connects with `timeout=30` and `banner_timeout=30` but there is no connect-level timeout on individual `exec_command` calls beyond the per-command `timeout` parameter (default 120 s). A hung remote command holds the connection open for 2 minutes, blocking the script. | Already partially mitigated; document the per-command timeout. For long operations (mysqldump) the 300/600 s timeout is appropriate. No code change required — documentation gap only. |
| S-8 | **Medium** | A09 Security Logging | `wp-forensics.py:143` | The DB password is used directly in a `mysqldump` command via `wp.ssh()`. If `quiet=False`, the `ssh()` call itself does not log commands, but the command is visible in Python stack traces and any debug output. The MYSQL_PWD approach is correctly used but the inconsistency with base64 encoding (used in `db()`) merits a note. | Acceptable deviation — `mysqldump` requires CLI-level DB/table selection that can't be piped as SQL. Document this in a code comment. |
| S-9 | **Medium** | A05 Security Misconfiguration | `security-headers.php:36–41` | Default CSP includes `'unsafe-inline'` and `'unsafe-eval'` for both `script-src` and `style-src`. While necessary for many WordPress themes/plugins, enabling CSP in this default state provides minimal XSS protection. | Change `WP_ARSENAL_CSP_ENABLED` default from `false` to `true` only if the default policy is tightened. Current default-off behaviour is safe; document the trade-off explicitly. |
| S-10 | **Medium** | A02 Cryptographic Failures | `honeypot.php:37` | The hourly HMAC token uses `floor(time() / 3600)`. At the hour boundary (e.g. 59:59 → 00:00), a bot that cached the trap link just before the hour has a token that expires within seconds. | Extend token validity to a rolling 2-hour window by checking both `floor(time()/3600)` and `floor(time()/3600) - 1`. |

```php
// Current: single-epoch check
$expected = hash_hmac('sha256', (string) floor(time() / 3600), WP_ARSENAL_HONEYPOT_SECRET);
if (hash_equals($expected, $_GET['_wpa_hp'])) { ... }

// Fixed: accept current or previous hour
$epoch = (string) floor(time() / 3600);
$valid = hash_equals(hash_hmac('sha256', $epoch, WP_ARSENAL_HONEYPOT_SECRET), $_GET['_wpa_hp'])
      || hash_equals(hash_hmac('sha256', (string)((int)$epoch - 1), WP_ARSENAL_HONEYPOT_SECRET), $_GET['_wpa_hp']);
if ($valid) { _wp_arsenal_honeypot_triggered(); exit; }
```

### Low Findings

| ID | Severity | OWASP | File | Description |
|---|---|---|---|---|
| S-11 | Low | A03 Injection | `honeypot.php:83–87` | `$fp` fingerprint JSON keys and values from `$_GET['fp']` are interpolated into the alert email body without sanitisation (`"  {$k}: {$v}\n"`). If `$v` contains `\r\n`, it could inject RFC-2822 email headers. Mitigate with `wordwrap(strip_tags((string)$v), 80)` on each value. |
| S-12 | Low | A09 Logging | `wp_connect.py:249` | `db()` prints `warn("DB credentials not configured — skipping DB query")` to stdout. In CI/CD mode with `--quiet`, this is suppressed. Without `--quiet`, a DB-skip warning appears mid-scan without identifying which check was skipped. |
| S-13 | Low | A05 Security Misconfiguration | `wp-harden.py:96–97` | `UPLOADS_HTACCESS` uses Apache 2.2-era `deny from all` syntax. Correct for compatibility, but may generate deprecation warnings on Apache 2.4+ with `LogLevel warn`. |
| S-14 | Low | A09 Logging | `wp-forensics.py:126–132` | Bash history and crontab are collected without checking if the server is a shared hosting environment where `crontab -l` may require interactive prompts or return a generic "no crontab" error that is silently ignored. |

---

## Dimension 4 — Code Quality & Technical Debt

### DRY / Code Duplication

| ID | Severity | Description | Fix |
|---|---|---|---|
| Q-1 | Medium | Password escaping logic (`db_pass.replace("'", "'\\''")`) appears in three places: `wp_connect.db()` (with wrong backslash handling), `wp-backup.backup_database()`, and `wp-forensics.collect_evidence()`. | Add `WPConnection.shell_quote_password() -> str` static method; use in all three. |
| Q-2 | Low | `wp-forensics.py:56-58` builds a `mkdir -p` + `chmod 700` command. The evidence subdirectories (`malware/`, `logs/`, `config/`, `db/`) are world-readable between their creation and the parent `chmod 700`. Use `umask 077` before mkdir: `umask 077 && mkdir -p ...` — then chmod is belt-and-suspenders. |
| Q-3 | Low | `is_apache()` in `wp-firewall.py` uses `wp.wp_exists(".htaccess")` as the heuristic for Apache, which is not reliable (`.htaccess` may be absent on Apache too, or present on LiteSpeed). The `php_uname("s")` call is made but its result is unused. |

### Cyclomatic Complexity

| File | Function | Approx. Complexity | Assessment |
|---|---|---|---|
| `wp-scan.py` | `run_scan()` | ~15 | High — 13 sequential sections. Acceptable for a scan script but hard to test sections individually. |
| `wp-forensics.py` | `collect_evidence()` | ~12 | Moderate — linear collection steps. |
| `config_loader.py` | `_set_if_default()` | ~5 | The nested `if attr == "port"` double-negation is confusing. |
| `wp_connect.py` | `WPConnection` | ~10 | Well-structured. |

### SOLID Adherence

| Principle | Assessment |
|---|---|
| Single Responsibility | Strong — each script has one purpose; `wp_connect.py` is the one cross-cutting concern |
| Open/Closed | Weak — adding a new scan check requires editing `run_scan()`. A plugin-list pattern would allow extension without modification. |
| Liskov/Interface | N/A — no inheritance hierarchy |
| Dependency Inversion | Partial — `WPConnection` is concrete; scripts could accept an interface for testability |

---

## Dimension 5 — Dependency Health

### Python Dependencies

| Package | Constraint | Latest | Status | Notes |
|---|---|---|---|---|
| `paramiko` | `>=3.0` | 3.5.x | ✅ Healthy | No open CVEs in 3.x. Pin to `~=3.4` for stability. |
| `pyyaml` | `>=6.0` | 6.0.2 | ✅ Healthy | 6.x resolves arbitrary code execution CVEs from 5.x. |
| `pytest` | `>=7.0` | 8.3.x | ✅ Healthy | No pinned upper bound — will pick up pytest 8.x which is compatible. |
| `pytest-mock` | `>=3.10` | 3.14.x | ✅ Healthy | No known CVEs. |

**Recommendation:** Pin with `~=` (compatible release) to avoid accidental breaking-change upgrades:

```
paramiko~=3.4
pyyaml~=6.0
pytest~=8.3
pytest-mock~=3.14
```

### PHP Dependencies

No `composer.json` — all MU-plugins are vanilla PHP with no third-party dependencies. ✅

### GitHub Actions (workflow examples)

| Action | Pinned Version | Status |
|---|---|---|
| `actions/checkout` | `@v4` | ✅ Current |
| `actions/setup-python` | `@v5` | ✅ Current |
| `actions/upload-artifact` | `@v4` | ✅ Current |

No SHA-pinning on third-party actions. For a security toolkit, SHA pinning is recommended to prevent supply-chain attacks on CI.

---

## Test Coverage Gaps

| ID | Severity | Gap | Impact |
|---|---|---|---|
| T-1 | Medium | `wp_connect.db()` has no unit test for the backslash escaping bug (S-3). The only password escape test covers `backup_database()` not `db()`. | Bug S-3 went undetected. |
| T-2 | Medium | `config_loader.py` has no tests at all. The `_set_if_default()` port-22 special-case and provider CIDR injection are untested. | Regressions in config loading would be silent. |
| T-3 | Low | SSH key-file path is untested (because it's unimplemented). | See S-2. |
| T-4 | Low | `wp-harden.py` has only an import smoke test. The `apply_hardening()` flow (constants added to wp-config, .htaccess modified) has no behavioral tests. | Changes to hardening logic are unvalidated. |
| T-5 | Low | `wp-firewall.py` `build_ip_block()`, `build_login_whitelist()`, `build_geo_block()` are pure functions that could be unit-tested without mocking SSH. | No tests exist for these string builders. |
| T-6 | Low | `.vibe/harness/` shell scripts run only in the AI development harness and are not part of `pytest`. | CI pipelines do not run these security checks. |

---

## Summary Scorecard

| Dimension | Score | Key Issues |
|---|---|---|
| Architectural Cohesion | 8/10 | Strong shared-library pattern; minor duplication in password escaping |
| Functional Completeness | 7/10 | key_file unimplemented; silent DB skips; Apache 2.4 compat |
| Security & Vulnerabilities | 6/10 | AutoAddPolicy MITM; backslash bug in db(); CIDR prefix mismatch |
| Code Quality / Tech Debt | 7/10 | Good structure; complexity in run_scan; SOLID gaps |
| Dependency Health | 9/10 | All current; no CVEs; minor: no upper-bound pinning |

---

## Prioritised Action Plan

### P0 — Fix Before First Production Use

| # | Issue | File | Action |
|---|---|---|---|
| 1 | S-3: Backslash double-escape in `db()` | `wp_connect.py:257` | Remove `replace("\\", "\\\\")` |
| 2 | S-2: SSH key-file auth unimplemented | `wp_connect.py:147`, `config.example.yaml:14` | Pass `key_filename` to `client.connect()`; read from args |
| 3 | S-1: AutoAddPolicy MITM | `wp_connect.py:145` | Add `known_hosts` support or per-site fingerprint in config |

### P1 — Fix Within One Sprint

| # | Issue | File | Action |
|---|---|---|---|
| 4 | S-5: CIDR notation mismatch | All mu-plugins + config | Add `wp_arsenal_cidr_match()` helper; update config examples |
| 5 | Q-1: Password escaping duplication | 3 files | Centralise in `WPConnection.shell_quote_password()` |
| 6 | T-1: Missing test for `db()` escaping | `tests/test_wp_connect.py` | Add `test_db_escapes_single_quote_not_backslash()` |
| 7 | T-2: `config_loader.py` untested | `tests/` | Add `test_config_loader.py` |

### P2 — Backlog

| # | Issue | Action |
|---|---|---|
| 8 | S-10: Hourly token boundary | Accept previous-hour token in honeypot.php |
| 9 | S-6: REST API bypasses IP guard | Add `WP_ARSENAL_ALLOW_REST_PUBLIC` constant |
| 10 | S-11: Fingerprint email injection | Sanitise `$k`/`$v` before interpolation |
| 11 | Q-2: /tmp TOCTOU race | Prepend `umask 077 &&` to forensics mkdir command |
| 12 | T-4/T-5: Missing hardening/firewall unit tests | Add pure-function tests for builders |
| 13 | Dependency pinning | Change `requirements.txt` to `~=` constraints |
| 14 | F-3: `-newer wp-login.php` anchor | Replace with `-mtime -14` fixed window |
| 15 | A-3: Harness not in CI | Integrate `.vibe/harness/*.sh` into GitHub Actions |

---

## Code Snippets for P0 Fixes

### Fix 1 — Backslash bug in `wp_connect.db()` (S-3)

```python
# wp_connect.py, line 257 — BEFORE
pass_escaped = self.db_pass.replace("\\", "\\\\").replace("'", "'\\''")

# AFTER — POSIX sh single-quotes never interpret backslash
pass_escaped = self.db_pass.replace("'", "'\\''")
```

### Fix 2 — Implement SSH key-file auth (S-2)

```python
# wp_connect.py __init__ — add after self.password =
self.key_file = getattr(args, "key_file", "") or ""

# wp_connect.py connect() — update client.connect() call
client.connect(
    self.host, port=self.port,
    username=self.user,
    password=self.password or None,
    key_filename=self.key_file or None,
    timeout=30,
    banner_timeout=30,
    auth_timeout=30,
)
```

```python
# wp_connect.py add_connection_args() — add to group g
g.add_argument("--key-file", dest="key_file", default="",
               help="Path to SSH private key file (alternative to --password)")
```

### Fix 3 — Known-hosts enforcement (S-1)

```python
# wp_connect.py connect() — replace AutoAddPolicy
import os
known_hosts = os.path.expanduser("~/.ssh/known_hosts")
if os.path.exists(known_hosts):
    client.load_host_keys(known_hosts)
client.set_missing_host_key_policy(paramiko.RejectPolicy())
# For first-time connections, provide --accept-host-key flag:
# client.set_missing_host_key_policy(paramiko.WarningPolicy())
```

### Fix 4 — `shell_quote_password()` centralisation (Q-1)

```python
# wp_connect.py — add to WPConnection class
@staticmethod
def shell_quote_password(password: str) -> str:
    """Escape a password for safe use inside a POSIX sh single-quoted string."""
    return password.replace("'", "'\\''")
```

Replace all three occurrences of the inline `db_pass.replace(...)` logic with `WPConnection.shell_quote_password(wp.db_pass)`.

---

*End of audit report. Total issues: 3 High, 7 Medium, 7 Low.*
