---
name: wp-plugin-restore
description: >
  Restore deleted WordPress plugins from a sibling WP site on the same server
  (instant copy, no download) or from wordpress.org API. Then optionally
  reactivates them in the database. Works on any host, any WP installation.
metadata:
  type: management
  script: scripts/restoration/wp-plugin-restore.py
  requires: paramiko
---

# WP-PLUGIN-RESTORE — Restore Deleted Plugins

## When to use

When plugins have been deleted from `wp-content/plugins/` but are still listed
in `active_plugins`. WordPress renders raw `post_content` (no Elementor layout)
because plugin hooks never register.

## Usage

```bash
# Restore from sibling WP on same server (fastest — no download, instant copy)
python scripts/restoration/wp-plugin-restore.py \
  --config config/config.yaml \
  --plugins elementor,cloudflare,seo-by-rank-math \
  --sibling-plugins-path /var/www/html/anothersite/wp-content/plugins \
  --activate

# Restore from wordpress.org (when no sibling available)
python scripts/restoration/wp-plugin-restore.py \
  --config config/config.yaml \
  --plugins elementor,imagify,auto-sizes \
  --activate
```

## All flags

| Flag | Description |
|------|-------------|
| `--plugins` | Comma-separated slugs to restore |
| `--sibling-plugins-path` | Path to another WP site's plugins/ dir on same server |
| `--activate` | Re-add to active_plugins in DB after restoring |
| `--dry-run` | Preview only — no changes |

## Finding a sibling plugins path

If you have multiple sites on the same hosting account, they share the server
filesystem. Find the other site's WP root, then append `/wp-content/plugins`.

```bash
# SSH in and find other WP installations
find / -name "wp-config.php" 2>/dev/null | grep -v node_modules
```

## Plugin slug reference (common plugins)

| Common name | WP.org slug |
|-------------|------------|
| Rank Math SEO | seo-by-rank-math |
| Header Footer Elementor | header-footer-elementor |
| Insert Headers and Footers | insert-headers-and-footers |
| Kadence Starter Templates | kadence-starter-templates |
| WooCommerce | woocommerce |
| Yoast SEO | wordpress-seo |
| Contact Form 7 | contact-form-7 |

## After restoring

Run `wp-elementor-fix` if the site uses Elementor — restoring plugins alone
doesn't clear the CSS cache.
