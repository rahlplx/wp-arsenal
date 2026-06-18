# Vibe Learnings Index — wp-arsenal

Last updated: 2026-06-19

---

## Anti-Patterns

| File | Summary | Severity | Date |
|------|---------|----------|------|
| [credential-in-process-args.md](anti-patterns/credential-in-process-args.md) | DB passwords in CLI args visible in `ps` | CRITICAL | 2026-06-18 |
| [shell-expansion-in-grep-pattern.md](anti-patterns/shell-expansion-in-grep-pattern.md) | `repr(pattern)` doubles backslashes → broken regex | HIGH | 2026-06-18 |
| [str-vs-int-http-codes.md](anti-patterns/str-vs-int-http-codes.md) | `http_code()` returning str vs int → always False | HIGH | 2026-06-18 |
| [user-input-in-shell-command.md](anti-patterns/user-input-in-shell-command.md) | URL interpolated raw in curl cmd → shell injection | HIGH | 2026-06-18 |
| [secret-in-html-output.md](anti-patterns/secret-in-html-output.md) | Raw PHP SECRET constant in HTML href/JS → leaked to visitors | HIGH | 2026-06-19 |
| [sftp-channel-leak.md](anti-patterns/sftp-channel-leak.md) | SFTPClient.from_transport() in loop → channel leak | MEDIUM | 2026-06-19 |
| [world-readable-tmp.md](anti-patterns/world-readable-tmp.md) | /tmp archive without chmod → readable by all server users | MEDIUM | 2026-06-19 |

---

## Patterns

| File | Summary | Category | Date |
|------|---------|----------|------|
| [importlib-for-hyphenated-scripts.md](patterns/importlib-for-hyphenated-scripts.md) | Use importlib for scripts with hyphens in filename | Testing | 2026-06-18 |
| [mysql-pwd-env-var.md](patterns/mysql-pwd-env-var.md) | MYSQL_PWD env var instead of -p flag | Security | 2026-06-18 |
| [shared-library-config-loading.md](patterns/shared-library-config-loading.md) | Load config in __init__ so all methods get it | Architecture | 2026-06-18 |
| [wpscan-intelligence-mining.md](patterns/wpscan-intelligence-mining.md) | Use WPScan CVE data to build detection signatures | Security | 2026-06-18 |
| [hmac-derived-token.md](patterns/hmac-derived-token.md) | hash_hmac(secret, time_slot) for safe HTML embedding | Security | 2026-06-19 |
| [lifecycle-managed-sftp.md](patterns/lifecycle-managed-sftp.md) | wp._get_sftp() not SFTPClient.from_transport() | Resource management | 2026-06-19 |

---

## Project Lessons

| File | Date | Tests | Bugs Fixed |
|------|------|-------|-----------|
| [wp-arsenal-2026-06-18.md](projects/wp-arsenal-2026-06-18.md) | 2026-06-18 | 51 | 7 |
| [wp-arsenal-2026-06-19.md](projects/wp-arsenal-2026-06-19.md) | 2026-06-19 | 63 | 9 |

---

## Evolutions

| File | Proposals |
|------|---------|
| [2026-06-18-evolution.md](evolutions/2026-06-18-evolution.md) | 3 new rules, 3 new harness checks |
| [2026-06-19-grill-me.md](evolutions/2026-06-19-grill-me.md) | 5-persona grill-me debate, 5 action items |

---

## Quick Reference — By Category

### Shell Security
- shlex.quote() for any user-controlled value in shell command → [user-input-in-shell-command.md](anti-patterns/user-input-in-shell-command.md)
- WP_PAT=shlex.quote(pattern) for grep → [shell-expansion-in-grep-pattern.md](anti-patterns/shell-expansion-in-grep-pattern.md)
- POSIX sh single-quotes are fully literal → rule: posix-sh-single-quote-semantics

### Credential Handling
- MYSQL_PWD env var → [mysql-pwd-env-var.md](patterns/mysql-pwd-env-var.md)
- No -p flag → [credential-in-process-args.md](anti-patterns/credential-in-process-args.md)
- Secrets → HMAC → HTML → [hmac-derived-token.md](patterns/hmac-derived-token.md)
- Secrets never in HTML output → [secret-in-html-output.md](anti-patterns/secret-in-html-output.md)

### Resource Management
- SFTP via _get_sftp() only → [lifecycle-managed-sftp.md](patterns/lifecycle-managed-sftp.md)
- /tmp dirs need chmod 700 → [world-readable-tmp.md](anti-patterns/world-readable-tmp.md)

### Testing
- importlib for hyphenated filenames → [importlib-for-hyphenated-scripts.md](patterns/importlib-for-hyphenated-scripts.md)
- Behavioral tests over source inspection (SFTP, /tmp)
- Test semantic guarantee not escape sequence characters (shlex.quote)
