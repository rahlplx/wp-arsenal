---
name: wp-restore-core
description: >
  Restore WordPress core files from a clean wordpress.org download.
  Overwrites core files only — preserves wp-content/ and wp-config.php.
  Use when core files have been tampered with or corrupted by malware.
triggers:
  - restore core
  - WordPress core corrupted
  - reinstall WordPress
  - core files tampered
  - fix WordPress installation
---

# Skill: wp-restore-core

Downloads a clean WordPress release from wordpress.org and rsyncs it over
the existing installation, overwriting only core files. `wp-content/` and
`wp-config.php` are always excluded.

## What it does

1. Reads installed WP version (or use `--wp-version` to specify one)
2. Downloads `wordpress-{version}.tar.gz` from wordpress.org to `/tmp/`
3. Rsyncs core files into the WP root — **excluding** `wp-content/` and `wp-config.php`
4. Removes the temp download
5. Fixes file permissions on restored files

## Usage

```bash
# Restore using installed version (auto-detected)
python scripts/restoration/wp-restore-core.py --config config/config.yaml

# Restore a specific version
python scripts/restoration/wp-restore-core.py --config config/config.yaml --wp-version 6.5.4

# Dry-run preview
python scripts/restoration/wp-restore-core.py --config config/config.yaml --dry-run
```

## When to use

- `wp-deep-audit.py` reports modified core files
- `wp-scan.py` finds PHP shells in `wp-includes/` or `wp-admin/`
- Site produces PHP errors after an attack (attacker overwrote core files)
- Version mismatch detected between database and filesystem

## Finding the installed WP version

```bash
# Via SSH:
grep wp_version /path/to/wp-includes/version.php
# Or from the database:
SELECT option_value FROM wp_options WHERE option_name = 'db_version';
```

## What is preserved

- `wp-content/` — all themes, plugins, uploads
- `wp-config.php` — all site credentials and constants
- `.htaccess` — all custom rules

## After running

Always run `wp-chmod-fix.py` after restoring core to ensure correct permissions.
