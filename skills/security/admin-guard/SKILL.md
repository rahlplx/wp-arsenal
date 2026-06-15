---
name: admin-guard
description: >
  MU-plugin that restricts wp-login.php and wp-admin/ to trusted IP ranges at the
  PHP level. Belt-and-suspenders alongside .htaccess whitelisting. Has a safety
  valve: if no trusted CIDRs are configured, all IPs are allowed (so you can't
  lock yourself out).
triggers:
  - restrict admin access
  - whitelist admin IP
  - wp-admin IP restriction
  - block admin from outside
  - protect login page
---

# Skill: admin-guard (MU-plugin)

PHP-level restriction of `wp-login.php` and `wp-admin/` to trusted IP ranges.
Runs at `init` priority 1 — before any plugin or theme code.

## Deploy

```bash
# 1. Set your trusted IPs first (CRITICAL — do this before deploying)
# Edit wp-content/mu-plugins/wp-arsenal-config.php:
# define('WP_ARSENAL_TRUSTED_CIDRS', ['YOUR_HOME_IP', 'YOUR_OFFICE_IP']);

# 2. Deploy
cp scripts/hardening/mu-plugins/admin-guard.php \
   /path/to/wp-content/mu-plugins/
```

**Always configure `WP_ARSENAL_TRUSTED_CIDRS` before deploying.** The plugin
has a built-in safety valve: if no trusted CIDRs are set, all IPs are allowed
(so you can't lock yourself out), but this defeats the purpose.

## What is protected vs allowed

| URL | Behaviour |
|-----|-----------|
| `/wp-login.php` | Trusted IPs only |
| `/wp-admin/*.php` | Trusted IPs only |
| `/wp-admin/admin-ajax.php` | **Allowed from any IP** (public themes use it) |
| `/wp-admin/admin-post.php` | **Allowed from any IP** (form handlers) |
| `/wp-json/` (REST API) | **Allowed from any IP** (headless/API clients) |
| Public pages | Not affected |

## Configuration in wp-arsenal-config.php

```php
define('WP_ARSENAL_TRUSTED_CIDRS', [
    '203.0.113.',      // Your home IP (first 3 octets)
    '198.51.100.',     // Your office IP
    '127.0.0.1',       // Localhost
    '82.165.',         // IONOS server monitoring (if on IONOS)
]);
```

## Working with dynamic IPs

If your home IP changes, use a VPN with a fixed exit IP, or:

1. Set up a **VPN** with a static IP — add that to `TRUSTED_CIDRS`
2. Or set up **Cloudflare Access** in front of `/wp-admin` (Zero Trust)
3. Or use `wp-firewall.py` with `--allow-admin-ip YOUR_CURRENT_IP` to update `.htaccess` rules quickly

## Difference from ip-blocker.php

| Plugin | Scope | Trigger |
|--------|-------|---------|
| `ip-blocker.php` | Entire site blocked | IP in `WP_ARSENAL_BLOCKED_CIDRS` |
| `admin-guard.php` | Admin area only | IP **not** in `WP_ARSENAL_TRUSTED_CIDRS` |

Use both together: `ip-blocker` for known-bad IPs, `admin-guard` to lock admin
to your known-good IPs.
