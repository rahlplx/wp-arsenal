# SKILL: wp-theme-restore — Full Theme Restoration & Web UI/UX Verification

## Purpose

Complete WordPress theme recovery tool. Understands the **full WordPress theme layer** (database + filesystem + HTTP) and fixes all of it, not just the files. Goes beyond file restoration to verify the end-user experience is healthy after recovery.

## When to use

- Theme broken after attack (files deleted/modified by attacker)
- Theme blank page after update
- White screen of death with no visible error
- CSS missing / unstyled frontend
- After migrating WordPress to new host
- After restoring from backup (to verify nothing is missing)
- Before and after any major theme change

## WordPress Theme Architecture — What Gets Restored

```
DATABASE LAYER
  wp_options:
    template          ← active parent theme slug
    stylesheet        ← active theme slug (differs from template if child theme)
    current_theme     ← display name (WP Admin label)
    theme_mods_{slug} ← Customizer settings
    rewrite_rules     ← permalink structure (must flush after theme switch)
    elementor_css_version  ← bumping this invalidates Elementor CSS cache
  wp_postmeta:
    _elementor_data   ← page builder JSON (layout data)
    _elementor_css    ← per-page generated CSS (cached)
    _elementor_global_css ← global styles CSS
    _wp_page_template ← custom page template assignment

FILESYSTEM LAYER
  wp-content/themes/{slug}/
    style.css         ← REQUIRED: Theme Name, Version, Template headers
    index.php         ← REQUIRED: fallback template
    functions.php     ← enqueues, hooks, custom post types
    screenshot.png    ← WP Admin thumbnail (optional)
    *.php             ← template hierarchy
    assets/ css/ js/  ← frontend assets
  wp-content/uploads/elementor/css/
    post-{id}.css     ← Elementor generated CSS (safe to delete — regenerates)
  wp-content/cache/   ← Caching plugin cache (safe to delete — regenerates)

HTTP LAYER
  Homepage, WP login, Search, Feed, RSS
  WooCommerce: /shop/ /cart/ /checkout/
  All CSS/JS/font assets must return HTTP 200
```

## Step-by-Step Restoration (what the script does)

| Step | What Happens | Safe to skip? |
|------|-------------|---------------|
| 1 | Pre-restore backup of current theme dir | No — always snapshot before overwriting |
| 2 | Restore theme files from .tar.gz backup | Skip with --verify-only |
| 3 | Repair DB: template, stylesheet, current_theme, siteurl/home check | No |
| 4 | Clear all caches: Elementor CSS, WP Rocket, W3TC, LiteSpeed, rewrite rules | No |
| 5 | Verify frontend: HTTP status per page, CSS/JS loads, Elementor renders | No |
| 6 | Final HTTP check on homepage | No |

## Usage

```bash
# Verify-only (no changes — assess damage first)
python scripts/restoration/wp-theme-restore.py --config config/config.yaml --verify-only

# Audit WordPress folder structure only
python scripts/restoration/wp-theme-restore.py --config config/config.yaml --structure-only

# Full restoration from backup
python scripts/restoration/wp-theme-restore.py --config config/config.yaml \
    --theme kadence \
    --from-backup /local/path/kadence-backup.tar.gz

# Dry-run (shows what would happen without making changes)
python scripts/restoration/wp-theme-restore.py --config config/config.yaml \
    --theme kadence --dry-run

# With explicit credentials (no config file)
python scripts/restoration/wp-theme-restore.py \
    --host ssh.yourhost.com --user sshuser --password sshpass \
    --wp-path /var/www/html/yoursite \
    --site-url https://yoursite.com \
    --theme kadence --from-backup /path/kadence.tar.gz
```

## WordPress Folder Structure — Required Layout

```
/var/www/html/yoursite/         ← WP root (--wp-path)
├── wp-config.php               ← REQUIRED: DB credentials, salts, table prefix
├── index.php                   ← REQUIRED: WordPress entry point
├── wp-login.php                ← REQUIRED: Login endpoint
├── wp-admin/                   ← REQUIRED: Admin dashboard
├── wp-includes/                ← REQUIRED: WordPress core library
│   ├── functions.php
│   └── class-wp.php
└── wp-content/                 ← REQUIRED: User content
    ├── index.php               ← REQUIRED: Security file (blank, blocks dir listing)
    ├── themes/                 ← REQUIRED: Theme directory
    │   ├── {active-slug}/      ← REQUIRED: Active theme must exist here
    │   │   ├── style.css       ← REQUIRED: Theme header file
    │   │   ├── index.php       ← REQUIRED: Template fallback
    │   │   ├── functions.php   ← Theme setup (enqueue, supports, etc.)
    │   │   └── ...             ← Template hierarchy, assets
    │   └── {parent-slug}/      ← REQUIRED if child theme is active
    ├── plugins/                ← Plugin directories
    ├── uploads/                ← User media (images, PDFs, etc.)
    │   └── elementor/css/      ← Elementor generated CSS (auto-created)
    ├── cache/                  ← Caching plugin cache (auto-created, safe to delete)
    │   ├── wp-rocket/
    │   ├── LiteSpeed/
    │   └── minify/             ← W3 Total Cache
    └── mu-plugins/             ← Must-use plugins (load without activation)
```

## Files that should NOT exist (run --structure-only to detect)

| File | Risk | Fix |
|------|------|-----|
| `wp-config.php.bak` | Exposes DB credentials | Delete immediately |
| `readme.html` | Discloses WP version | Delete |
| `license.txt` | Minor info disclosure | Delete |
| `.maintenance` | Stuck in maintenance mode | Delete |
| `wp-content/debug.log` | May contain sensitive data | Delete or move out of webroot |
| PHP files in `uploads/` | Backdoor indicator | Investigate + delete |
| PHP files in `cache/` | Backdoor indicator | Investigate + delete |

## Common Findings and What They Mean

### "Active theme directory missing"
**Cause:** Theme files deleted (attack), failed update, wrong --wp-path  
**Fix:** `--from-backup /path/kadence.tar.gz` to restore files

### "CSS stylesheet returns HTTP 404"
**Cause:** Theme CSS cache broken, wrong asset URL in DB, CDN misconfiguration  
**Fix:** Run with `--verify-only` first, then `--theme` to fix DB + clear caches

### "Elementor content: not detected in page source"
**Cause:** Elementor CSS regeneration failed, page builder data corrupted, plugin conflict  
**Fix:** Delete `wp-content/uploads/elementor/css/*.css` + bump elementor_css_version in DB  
(the script does this automatically in Step 4)

### "siteurl ≠ home"
**Cause:** Migration, broken update, manual DB edit  
**Fix:** Set both to the same URL in wp_options (the script flags this but does not auto-fix to avoid breaking intentional setups)

### "PHP error visible in homepage source"
**Cause:** Fatal PHP error, broken plugin conflict after theme switch  
**Fix:** Check `wp-content/debug.log`, activate default theme in DB manually:
```sql
UPDATE wp_options SET option_value='twentytwentyfour' WHERE option_name='template';
UPDATE wp_options SET option_value='twentytwentyfour' WHERE option_name='stylesheet';
```

### "Mixed content: N HTTP src= on HTTPS page"
**Cause:** Hardcoded http:// in theme or content, CDN not configured for HTTPS  
**Fix:** Run Better Search Replace plugin or wp-cli to update URLs in DB

## Related Scripts

| Script | Purpose |
|--------|---------|
| `wp-theme-restore.py` | This script — full restore + verify |
| `wp-theme-audit.py` | Security audit of theme files (malware detection) |
| `wp-elementor-fix.py` | Elementor-specific CSS/data repair |
| `wp-theme-switch.py` | Safely switch active theme (DB + cache) |
| `wp-child-theme.py` | Scaffold new child theme |
| `wp-backup.py` | Create backup before restoration |
| `wp-restore-core.py` | Restore WordPress core files (separate from theme) |

## Cache Systems Cleared (Step 4)

| Cache | Location | Method |
|-------|----------|--------|
| Elementor post CSS | `wp_postmeta._elementor_css` + `uploads/elementor/css/` | DB delete + file delete |
| Elementor version | `wp_options.elementor_css_version` | Increment (forces full regen) |
| WP Rocket | `wp-content/cache/wp-rocket/` | `rm -rf` |
| W3 Total Cache | `wp-content/cache/minify/` | `rm -rf` |
| LiteSpeed Cache | `wp-content/cache/LiteSpeed/` | `rm -rf` |
| WP rewrite rules | `wp_options.rewrite_rules` | Delete (regenerates on next request) |
| Theme transients | `wp_options._transient_theme_*` | DB delete |

## Frontend UX Checks (Step 5)

Every run verifies these URLs return expected HTTP codes:

| URL | Expected |
|-----|----------|
| Homepage `/` | 200 |
| WP login `/wp-login.php` | 200 |
| Search `/?s=test` | 200 |
| RSS feed `/feed/` | 200 |
| WooCommerce shop `/shop/` | 200, 301 |
| Cart `/cart/` | 200 |
| Checkout `/checkout/` | 200 |

Plus content checks on homepage:
- Mobile viewport meta tag present
- No mixed HTTP/HTTPS content
- No PHP error strings in source
- Elementor widget markup present (if Elementor active)
- CSS/JS assets all return HTTP 200 (up to 15 CSS, 10 JS files checked)
