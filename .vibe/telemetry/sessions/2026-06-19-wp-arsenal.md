# Session Telemetry — wp-arsenal — 2026-06-19

## Session Overview

| Metric | Value |
|--------|-------|
| Date | 2026-06-19 |
| Project | wp-arsenal |
| Phases | code-review → fix → harness → telemetry |
| Starting commit | `2087402` (vibe telemetry) |
| Ending commit | `0ba7997` (5 security fixes) |
| Tests at start | 51 |
| Tests at end | 57 |
| New tests | +6 (TestSecurityFixes class, RED-first) |

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

## Fixes Applied

### A: shlex.quote(pattern) — wp-scan.py + wp-deep-audit.py
- Root: `repr(pattern)` in POSIX sh single-quoted assignment doubles every `\`
- Effect: `\s*` → `\\s*` in WP_PAT → grep sees `\\s*` (literal backslash+s) not whitespace
- Impact: all `\$_(POST|GET|REQUEST|COOKIE)` and `['\"]` malware signatures broken
- Fix: `shlex.quote()` wraps in `'...'` without doubling backslashes

### B: shlex.quote(url) — wp_connect.py
- Root: URL from `--site-url` CLI arg interpolated raw inside `'...'` in curl command
- Effect: single-quote in URL closes the shell argument early; `&&` chains arbitrary command on remote server
- Fix: `shlex.quote(url)` handles internal single-quotes as `'\''`

### C: Revert backslash doubling — wp-backup.py
- Root: POSIX sh single-quotes pass `\` literally (no backslash special meaning inside `'...'`)
- Effect: password `foo\bar` → cmd `MYSQL_PWD='foo\\bar'` → mysqldump receives `foo\\bar` (wrong)
- Fix: `pass_escaped = wp.db_pass.replace("'", "'\\''")`  — no backslash replace

### D: isinstance guard — wp-user-audit.py
- Root: `'"slug"' in api_body` heuristic too broad; WP error JSON `{"data":{"slug":"..."}}` passes it
- Effect: `_json.loads()` returns dict; `for u in dict` iterates string keys; `u.get()` → AttributeError crash
- Fix: parse JSON first → `isinstance(parsed, list) and all(isinstance(u, dict) for u in parsed)` before loop
- Also: removes dead `elif rest_forbidden` branch; removes duplicate `import json as _json`

### E: if body guard — wp-scan.py section K
- Root: empty `http_body()` (curl timeout) passed to `"Index of" in body` without guard
- Effect: directory listing silently reported clean on connection failure (false-negative)
- Fix: `if body and ("Index of" in body or "Directory listing" in body)`

---

## Harness Results (2026-06-19)

| Check | Result |
|-------|--------|
| 1. Credential leak | ✅ PASS |
| 2. Shell injection | ✅ PASS (13 operator-config ssh() calls — trusted) |
| 3. mysqldump credential | ✅ PASS |
| 4. SQL input validation | ✅ PASS (false positive resolved) |
| 5. Error handling | ✅ PASS |
| 6. DB access controls | ✅ PASS |
| .vibe credential-exposure | ✅ PASS |
| .vibe importlib | ✅ PASS |
| .vibe grep-dollar-expansion | ✅ PASS |
| .vibe WP_PAT shlex | ✅ PASS |

**10/10 PASS**

---

## Key Learnings

1. **repr() ≠ shell-safe** — `repr(s)` wraps in Python quotes AND doubles backslashes. For POSIX sh: use `shlex.quote()` which gives `'...'` with `'\''` for internal single-quotes, no backslash mangling.
2. **POSIX sh single-quotes are fully literal** — inside `'...'`, backslash has NO special meaning. `'foo\bar'` → exactly `foo\bar`. Never double backslashes before putting value in single-quoted assignment.
3. **API response type ≠ assumed** — even when a heuristic string check passes, the JSON shape may differ from expected. Always `isinstance(parsed, list)` before iterating a parsed HTTP response.
4. **Heuristic detection order matters** — checking `'"slug"' in body` before `"rest_forbidden" in body` created an unreachable branch. Check for error patterns BEFORE checking for data patterns.
5. **Empty-string guards in body checks** — `if body and "pattern" in body` vs `if "pattern" in body`: the latter returns `False` on empty string (no crash) but silently skips the check. Make the guard explicit with `if body` to distinguish "found nothing" from "couldn't check".
