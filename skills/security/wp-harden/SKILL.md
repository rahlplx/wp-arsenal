---
name: wp-harden
description: >
  WordPress security hardening: adds security constants to wp-config.php,
  writes .htaccess protection rules (xmlrpc block, file browser disable,
  wp-includes protection), blocks PHP in uploads, disables pingbacks.
metadata:
  type: security
  script: scripts/hardening/wp-harden.py
  requires: paramiko
---

# WP-HARDEN — WordPress Security Hardening

Apply after every restore or on new sites. Run --dry-run first.

## Usage

```bash
python scripts/hardening/wp-harden.py \
  --host HOST --user USER --password PASS --wp-path PATH \
  --db-host DBHOST --db-user DBUSER --db-pass DBPASS \
  --db-name DBNAME --db-prefix wp_ [--dry-run]
```

## What it applies

| Hardening | How |
|-----------|-----|
| `DISALLOW_FILE_EDIT` | wp-config.php constant |
| `WP_DEBUG = false` | wp-config.php constant |
| `FORCE_SSL_ADMIN` | wp-config.php constant |
| WP includes protection | .htaccess RewriteRule block |
| xmlrpc.php block | .htaccess `<Files>` deny |
| File browsing disable | `Options -Indexes` |
| wp-config.php protection | .htaccess `<Files>` deny |
| wp-cron lock | .htaccess `<Files>` deny |
| PHP block in uploads | uploads/.htaccess |
| Pingbacks disabled | DB update to `closed` |
| File editor disabled | DB option |

## Idempotent

Safe to run multiple times — checks before inserting, uses markers to
avoid duplicate blocks.
