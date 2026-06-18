# Pattern: HMAC-Derived Token for Safe Output

## Problem
A secret is needed to authenticate a request, but the authentication token must appear in HTML or a URL that any visitor can read. Embedding the raw secret exposes it.

## Solution
Derive a time-bound one-way token from the secret using HMAC. The token proves knowledge of the secret without revealing it.

```php
// Server-side: derive token for output
$token = hash_hmac('sha256', (string)floor(time() / 3600), SECRET);
$url = add_query_arg('token', $token, home_url('/trap'));

// Server-side: verify incoming token  
$expected = hash_hmac('sha256', (string)floor(time() / 3600), SECRET);
if (hash_equals($expected, $_GET['token'])) {
    // authenticated — token is valid for this hour
}
```

## When to Use
- Any time a secret is needed to prove authenticity but the proof must travel over an insecure channel (HTML, URL, email)
- Honeypot links, CSRF tokens, email unsubscribe tokens, one-time links
- Never embed raw secrets as GET params, HTML attributes, or JS variables

## Properties
- **One-way**: attacker with token cannot recover SECRET
- **Time-bound**: token rotates hourly (adjust `3600` to your TTL)
- **Constant-time compare**: `hash_equals()` prevents timing attacks
- **No DB needed**: server can verify without storing anything

## Tradeoff
Token changes every hour — bookmarked trap links become invalid. For honeypots this is fine (bots follow fresh links). For user-facing links (email), use longer TTL or include the time slot in the URL so server can check ±1 window.

## Tested On
wp-arsenal honeypot.php, 2026-06-19
