# Anti-Pattern: Comparing HTTP Status Code String to Integer Tuple

## Symptom
A health check function always returns False even when site is healthy:
```python
code = wp.http_code(wp.site_url)   # returns "200" (str)
return code in (200, 301, 302)     # always False — comparing str to int
```
Effect: `site_responds()` returns False after every plugin update,
causing the updater to incorrectly report every plugin update breaks the site.
Entire `--all` update chain halts on first plugin.

## Root Cause
curl `%{http_code}` format string outputs digits as text. The function
that wraps it returns `str`. The caller assumed `int`.

## How vibe-stack Should Catch It
- Type annotation: `http_code() -> str` — if the caller does `code in (200,...)`,
  mypy/pyright will flag it
- Unit test: `assert isinstance(wp.http_code(...), str)` verifies the return type
- Test `site_responds()` with a mock returning `"200"` to catch the comparison bug

## Incident
wp-arsenal, 2026-06-18: wp-update.py:162 — `code in (200, 301, 302)`.
Caught by vibe-review (CRITICAL C2). Fixed to `code in ("200", "301", "302")`.
