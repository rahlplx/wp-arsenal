---
name: rate-limiter
description: >
  MU-plugin that rate-limits WordPress login attempts — no plugin required.
  After N failed logins from the same IP within a rolling window, locks out
  that IP for a configurable duration and sends an email alert.
triggers:
  - brute force protection
  - login rate limit
  - too many login attempts
  - lockout failed logins
  - brute force attack
---

# Skill: rate-limiter (MU-plugin)

Tracks failed login attempts per IP using WP transients. No plugin, no extra
database tables — uses WordPress's built-in transient API.

## Deploy

```bash
cp scripts/hardening/mu-plugins/rate-limiter.php \
   /path/to/wp-content/mu-plugins/

# Requires wp-arsenal-config.php to already be deployed (for TRUSTED_CIDRS)
```

## Default thresholds

| Constant | Default | Meaning |
|----------|---------|---------|
| `WP_ARSENAL_RATE_LIMIT_MAX` | `5` | Failures before lockout |
| `WP_ARSENAL_RATE_LIMIT_WINDOW` | `300` | Rolling window (seconds) = 5 min |
| `WP_ARSENAL_RATE_LIMIT_LOCKOUT` | `1800` | Lockout duration (seconds) = 30 min |

Override in `wp-arsenal-config.php`:

```php
define('WP_ARSENAL_RATE_LIMIT_MAX',     3);      // stricter: 3 attempts
define('WP_ARSENAL_RATE_LIMIT_WINDOW',  600);     // 10-minute window
define('WP_ARSENAL_RATE_LIMIT_LOCKOUT', 3600);    // 1-hour lockout
```

## What happens

1. Each failed login → increments transient `wp_arsenal_rl_{md5(ip)}`
2. At `MAX` failures → sets lockout transient + emails `WP_ARSENAL_ALERT_EMAIL`
3. Lockout → next login attempt returns HTTP 429 with wp_die message
4. Successful login → clears the failure counter (lockout persists for full duration)
5. Trusted CIDRs (`WP_ARSENAL_TRUSTED_CIDRS`) are never rate-limited

## Email alert content

When lockout triggers, sends to `WP_ARSENAL_ALERT_EMAIL`:
- IP address that was locked out
- Number of failed attempts
- Last attempted username
- Site URL and timestamp

## Pair with admin-guard for defence in depth

```
rate-limiter.php  — blocks after N failures (stops automated brute force)
admin-guard.php   — restricts admin to trusted IPs (stops all non-trusted access)
ip-blocker.php    — blocks known-bad IPs before WordPress loads
```
