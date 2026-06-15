---
name: wp-elementor-fix
description: >
  Fix broken Elementor rendering on any WordPress site after malware cleanup,
  plugin restore, or migration. Bumps elementor_css_version, clears _elementor_css
  postmeta, removes missing plugins from active_plugins, and clears transients
  and file cache. Works on any host.
metadata:
  type: management
  script: scripts/restoration/wp-elementor-fix.py
  requires: paramiko
---

# WP-ELEMENTOR-FIX — Restore Elementor Rendering

## Symptoms this fixes

- Site loads (HTTP 200) but shows plain text instead of the designed layout
- Page source has raw `<p>` tags, no `.elementor-*` classes
- WP Admin → Elementor → "Regenerate CSS" has no effect
- Site looks like unstyled HTML with huge fonts

## Root causes handled

1. Plugin missing from filesystem but still in `active_plugins` → PHP fatal → blank response
2. `_elementor_css` postmeta is stale → regeneration never triggered
3. `elementor_css_version` unchanged → WP serves old (missing) CSS
4. `wp-content/cache/` holding outdated output

## Usage

```bash
python scripts/restoration/wp-elementor-fix.py \
  --config config/config.yaml

# Or with explicit flags:
python scripts/restoration/wp-elementor-fix.py \
  --host ssh.host.com --user USER --password PASS \
  --wp-path /var/www/html/yoursite \
  --db-host localhost --db-user DBUSER --db-pass DBPASS \
  --db-name DBNAME --db-prefix wp_
```

## What it does (in order)

1. Verify `wp-content/plugins/elementor/` exists on filesystem
2. Remove missing plugins from `active_plugins` DB option
3. Bump `elementor_css_version` to current Unix timestamp
4. Delete all `_elementor_css` postmeta rows
5. Delete all `_transient_elementor*` rows
6. Delete all WP transients
7. Clear `wp-content/cache/`
8. Verify Elementor kit (global styles) is assigned
9. Verify `siteurl` == `home` (mixed-content guard)

## After running

Visit the site in a browser — CSS regenerates on the first page load.
If still broken, go to WP Admin → Elementor → Tools → Regenerate CSS & Data.

## If Elementor Pro is missing

Elementor Pro must be installed with a valid licence from elementor.com.
It cannot be restored from wordpress.org. Remove it from `active_plugins`
via this script, then reinstall manually: WP Admin → Plugins → Add New → Upload.
