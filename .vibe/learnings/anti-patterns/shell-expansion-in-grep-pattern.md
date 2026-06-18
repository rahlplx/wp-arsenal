---
name: shell-expansion-in-grep-pattern
description: Regex patterns with $_ silently break grep when interpolated into f-strings — bash expands $_ before grep sees it
metadata:
  type: feedback
---

## Anti-Pattern: Shell `$_` Expansion Breaks Malware Grep Patterns

### Symptom
Malware signatures with `$_(POST|GET|REQUEST|COOKIE)` patterns never match anything on a real server, even when matching PHP is clearly present. No error is raised — the grep just returns empty.

### Root Cause
Python f-string interpolation puts the raw regex pattern inside single quotes in a shell command:
```python
f"grep -rl -E '{pattern}' '{wp_path}'"
```
Bash expands `$_` (last argument of previous command) before grep receives the string. So `$_(POST|GET|REQUEST|COOKIE)` becomes `previousarg(POST|GET|REQUEST|COOKIE)` — a completely wrong pattern.

### Impact
**CRITICAL** — three of the highest-value malware signatures silently stopped working:
- `assert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)` → always clean
- `(system|exec|passthru|shell_exec)\s*\(\s*\$_(GET|POST|...)` → always clean
- `mail\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)` → always clean

### Fix
Pass the pattern via an environment variable so bash never sees the `$` in the regex:
```python
f"WP_PAT={repr(pattern)} grep -rl --include='*.php' -E \"$WP_PAT\" '{wp_path}'"
```
`repr()` wraps the pattern in Python quotes. The shell sees `$WP_PAT` (a variable reference), not the regex content.

**Why:** `$_` is a valid Bash variable (last argument). Any regex targeting PHP superglobals will contain `$_` and will silently break if interpolated directly.

**How to apply:** Any time a grep pattern is sourced from a variable (not a literal), use the env-var pattern. Add to harness: `check-ssh-fstring-injection.sh` already flags `.ssh(f"..."` calls for review.

[[mysql-pwd-env-var]] — same class of problem: data going into shell commands must be sanitised/isolated from shell expansion.
