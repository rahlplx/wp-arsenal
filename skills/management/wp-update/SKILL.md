---
name: wp-update
description: >
  Check and apply WordPress core and plugin updates via SSH.
  Verifies site responds after each update. Skips premium/private plugins.
  Supports check-only mode to see what's outdated without applying changes.
triggers:
  - update WordPress
  - update plugins
  - check for updates
  - WordPress outdated
  - plugin updates available
---

# Skill: wp-update

Checks wordpress.org for available updates to WordPress core and free plugins,
and optionally applies them. Verifies the site is still responding after each
update — stops the chain if the site goes down.

## Usage

```bash
# Check what's outdated (no changes made)
python scripts/management/wp-update.py --config config/config.yaml --check-only

# Update WordPress core only
python scripts/management/wp-update.py --config config/config.yaml --core

# Update specific plugins
python scripts/management/wp-update.py --config config/config.yaml --plugins elementor,rank-math,wordfence

# Update everything (core + all free plugins)
python scripts/management/wp-update.py --config config/config.yaml --all

# Preview what --all would do
python scripts/management/wp-update.py --config config/config.yaml --all --dry-run
```

## Important notes

**Premium plugins** (Elementor Pro, WooCommerce paid extensions, WPML, ACF Pro, etc.)
are not on wordpress.org — the script skips them automatically. Update these
via WP Admin > Plugins or via your plugin provider's account.

**Safety**: the script checks `HTTP 200` from `site_url` after each update.
If the site goes down, it stops and reports. You must investigate manually
before updating further.

## Always backup first

```bash
python scripts/management/wp-backup.py --config config/config.yaml
python scripts/management/wp-update.py --config config/config.yaml --all
```

## Regular maintenance schedule

```
Weekly:
  wp-backup → wp-update --check-only   (see what's outdated)
  
Monthly:
  wp-backup → wp-update --all → wp-scan  (update + verify clean)
```

## Checking which version is installed

```bash
# Via SSH:
grep wp_version /path/to/wp-includes/version.php

# Via this script:
python scripts/management/wp-update.py --config config/config.yaml --check-only
```
