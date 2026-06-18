# Anti-Pattern: Raw Secret in HTML Output

## Symptom
A PHP constant (`WP_ARSENAL_HONEYPOT_SECRET`) appears verbatim in every page's HTML as a GET parameter value in `<a href>` and `<script>` vars. Any visitor can read the secret by viewing page source.

## Root Cause
The secret was designed to authenticate the trap endpoint — but was used directly as the `_wpa_hp` query parameter value. This leaks the secret to every page visitor, not just trap-followers.

## Root Logic Error
The distinction between "a value that authenticates" and "a value that IS the secret" was collapsed. The secret should never leave the server.

## Fix Applied
```php
// Before (wrong — raw secret in HTML)
$trap = add_query_arg('_wpa_hp', WP_ARSENAL_HONEYPOT_SECRET, home_url('/'));

// After (correct — HMAC-derived time-bound token)
$token = hash_hmac('sha256', (string)floor(time() / 3600), WP_ARSENAL_HONEYPOT_SECRET);
$trap = add_query_arg('_wpa_hp', $token, home_url('/'));

// Trap handler verifies token, not raw secret
$expected = hash_hmac('sha256', (string)floor(time() / 3600), WP_ARSENAL_HONEYPOT_SECRET);
if (hash_equals($expected, $_GET['_wpa_hp'])) { ... }
```

## How vibe-stack Should Catch It
OWASP Stage 4 scan: grep for PHP constants used directly as HTML attribute values. Harness check: `grep -r "WP_.*SECRET\|SECRET.*html\|SECRET.*echo" --include="*.php"`.

The pattern to catch: any PHP `define()`d constant with "SECRET" or "KEY" in its name appearing in `echo`, template output, or `json_encode()`.

## Incident
wp-arsenal, honeypot.php, 2026-06-19. LOW severity (attacker who already has the URL could probe the endpoint anyway) but principle violation: secrets must never appear in client-visible output.
