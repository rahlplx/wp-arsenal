# Anti-Pattern: Unsanitised User/Attacker-Controlled Input in SSH Shell Commands

## Symptom
Attacker-controlled data from database (session tokens, user meta, post content)
passed directly into `wp.ssh(f"... '{value}' ...")` without validation:
```python
result = wp.ssh(f"whois '{ip}' 2>/dev/null ...")
# ip comes from wp_usermeta — attacker can write any value here
```

## Root Cause
Trusting data extracted from the database as "internal" — it was written there
by potentially hostile users. A malicious session_token entry containing
`'; rm -rf /tmp/evidence; echo '` would execute the injection on the analyst's server.

## How vibe-stack Should Catch It
For any `.ssh()` call that interpolates a value read from the database:
1. Validate format with regex before interpolation
2. For IPs specifically: `re.match(r"^[\d.:a-fA-F]+$", ip)`
3. For slugs/identifiers: use `WPConnection.sql_slug()` which raises on non-slug chars
4. For arbitrary strings: prefer parameterised patterns where possible, or base64-encode

Harness grep: `re.search(r'wp\.ssh\(f["\'].*\{[^}]*\}.*["\']', code)` — flag all
f-string interpolations in .ssh() calls for manual review.

## Incident
wp-arsenal, 2026-06-18: wp-attacker-profile.py `_whois_lookup()`.
Caught by vibe-review (HIGH H6). Fixed with IP regex validation guard.
