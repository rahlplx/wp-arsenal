---
name: security-headers
description: >
  MU-plugin that adds HTTP security headers to every WordPress response:
  X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy,
  Permissions-Policy, and optional Content-Security-Policy.
  Also removes WordPress version fingerprinting from HTML head.
triggers:
  - security headers
  - HTTP headers
  - HSTS
  - Content Security Policy
  - CSP
  - clickjacking protection
  - X-Frame-Options
---

# Skill: security-headers (MU-plugin)

Adds standard HTTP security headers to all WordPress responses. Works on every
page, login screen, and admin panel. No configuration required for basic
protection — everything is opt-in for stricter settings.

## Deploy

```bash
cp scripts/hardening/mu-plugins/security-headers.php \
   /path/to/wp-content/mu-plugins/
```

Works immediately with safe defaults. No configuration required.

## Headers added by default

| Header | Value | Protection |
|--------|-------|-----------|
| `X-Frame-Options` | `SAMEORIGIN` | Clickjacking |
| `X-Content-Type-Options` | `nosniff` | MIME sniffing |
| `X-XSS-Protection` | `1; mode=block` | Legacy XSS filter |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Referrer leakage |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=()` | Feature access |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | HTTPS enforcement (HTTPS only) |

Also removes:
- `X-Powered-By` header (PHP version fingerprinting)
- `Server` header (server software fingerprinting)
- WordPress version from `<head>` (`wp_generator` tag)

## Optional: stricter X-Frame-Options

```php
// wp-arsenal-config.php
define('WP_ARSENAL_X_FRAME', 'DENY');  // prevent all framing (more restrictive)
```

## Optional: Content Security Policy

CSP is **off by default** because WordPress themes commonly use inline scripts
and styles that would be blocked by a strict CSP.

```php
// wp-arsenal-config.php
define('WP_ARSENAL_CSP_ENABLED', true);

// Start with the permissive built-in default, then tighten over time:
define('WP_ARSENAL_CSP_POLICY',
    "default-src 'self'; "
    . "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://www.google-analytics.com; "
    . "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    . "img-src 'self' data: https:; "
    . "font-src 'self' https://fonts.gstatic.com; "
    . "frame-ancestors 'self';"
);
```

**CSP tip**: Use `Content-Security-Policy-Report-Only` first (report without blocking)
to discover what your site needs before enabling enforcement.

## Optional: custom HSTS max-age

```php
// wp-arsenal-config.php
define('WP_ARSENAL_HSTS_MAX_AGE', 63072000);  // 2 years
// Or disable HSTS (if you have mixed HTTP/HTTPS content):
define('WP_ARSENAL_HSTS_MAX_AGE', 0);
```

**Warning**: HSTS is only sent when WordPress detects an HTTPS connection. Once
set with a long `max-age`, browsers will refuse HTTP connections to your domain
for that duration. Only enable after you have permanent HTTPS.

## Verify headers are working

```bash
curl -sI https://yoursite.com | grep -E "X-Frame|X-Content|Strict|Referrer|Permissions|Content-Security"
```
