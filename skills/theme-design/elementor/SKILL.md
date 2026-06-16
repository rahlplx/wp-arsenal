---
name: elementor-guide
description: >
  Comprehensive guide to building, maintaining, and recovering Elementor-based
  WordPress sites. Covers the CSS pipeline, global styles (Kit), common
  post-attack failures and fixes, Pro vs Free features, and integration
  with Kadence and Hello Elementor themes.
triggers:
  - Elementor
  - Elementor broken
  - Elementor not rendering
  - Elementor CSS
  - Elementor Kit
  - Elementor Pro
  - Elementor recovery
  - page builder
---

# Elementor Guide

Elementor is a visual page builder that stores page layouts as JSON in
`_elementor_data` postmeta and generates CSS cached in `_elementor_css`.
Understanding this pipeline is essential for diagnosis and recovery.

## The Elementor Rendering Pipeline

```
1. Plugin loads → registers the_content filter at priority 9999
2. Filter checks _elementor_css postmeta for cached CSS
3. Cache miss OR elementor_css_version bumped → regenerates CSS
4. Outputs rendered HTML with <div class="elementor-*"> structure
5. Inline CSS injected in <head> or dequeued to file

Break step 1 (plugin missing/inactive) → raw <p> tags, no layout
Break step 2-3 (cache corrupt/stale) → layout renders but styles wrong
Break step 4 (JSON corrupt) → blank sections or missing widgets
```

## CSS Cache Architecture

| DB key | Purpose |
|--------|---------|
| `wp_options.elementor_css_version` | Version token — bump this to force CSS rebuild |
| `wp_postmeta._elementor_css` | Per-page CSS cache — delete to rebuild per page |
| `wp_options._elementor_global_css` | Global (Kit) CSS cache |
| `wp-content/cache/elementor/` | File-based CSS cache |

### Force full CSS rebuild

```bash
python scripts/restoration/wp-elementor-fix.py --config config/config.yaml
```

This bumps `elementor_css_version`, deletes all `_elementor_css` postmeta,
and clears the file cache — forcing Elementor to regenerate CSS on next page load.

## Elementor Kit (Global Styles)

The Kit is the control panel for global design tokens — fonts, colours, spacing,
and global widgets. It lives as a WordPress post with post type `elementor_library`
and `_elementor_template_type = 'kit'`.

```sql
-- Find the active Kit
SELECT post_id FROM wp_postmeta
WHERE meta_key = '_elementor_template_type' AND meta_value = 'kit';

-- Check which Kit is active
SELECT option_value FROM wp_options WHERE option_name = 'elementor_active_kit';
```

### Kit Design Tokens (Global Colours & Fonts)

Elementor Kit stores global tokens in its `_elementor_page_settings` postmeta.
These generate CSS custom properties:

```css
:root {
    --e-global-color-primary:    #6EC1E4;
    --e-global-color-secondary:  #54595F;
    --e-global-color-text:       #7A7A7A;
    --e-global-color-accent:     #61CE70;
    --e-global-typography-primary-font-family:   'Roboto';
    --e-global-typography-secondary-font-family: 'Roboto Slab';
}
```

Override in child theme `style.css` (load after Elementor styles):

```css
:root {
    --e-global-color-primary: #E53E3E;
}
```

## Pro vs Free Feature Map

| Feature | Free | Pro |
|---------|------|-----|
| Drag-drop visual editor | ✅ | ✅ |
| 40+ basic widgets | ✅ | ✅ |
| 90+ Pro widgets | ❌ | ✅ |
| Theme Builder (header/footer) | ❌ | ✅ |
| WooCommerce Builder | ❌ | ✅ |
| Popup Builder | ❌ | ✅ |
| Dynamic Content | ❌ | ✅ |
| Form Widget (advanced) | ❌ | ✅ |
| Global Widget editing | ❌ | ✅ |
| Role Manager | ❌ | ✅ |
| Custom CSS per-widget | ❌ | ✅ |

## Post-Attack Recovery Sequence

The most common attack scenario: plugins deleted → Elementor inactive →
site shows raw HTML instead of designed layout.

```bash
# 1. Restore missing plugins (including Elementor)
python scripts/restoration/wp-plugin-restore.py --config config/config.yaml \
    --plugins elementor --activate

# Elementor Pro must be re-purchased and installed manually via wp-admin
# (not on wordpress.org)

# 2. Fix Elementor CSS pipeline
python scripts/restoration/wp-elementor-fix.py --config config/config.yaml

# 3. Verify site renders
curl -sI https://yoursite.com | head -3
```

## Common Failure Modes

### Blank page / raw text (most common after attack)
**Cause**: Elementor plugin missing from filesystem but still in `active_plugins`.
WordPress tries to load the missing plugin → PHP fatal → blank output.

**Diagnosis**:
```sql
SELECT option_value FROM wp_options WHERE option_name='active_plugins';
-- Look for elementor/elementor.php — is the directory there?
```

**Fix**: `wp-plugin-restore.py` then `wp-elementor-fix.py`

---

### Layout visible but styles wrong (missing CSS)
**Cause**: `_elementor_css` cache corrupted or CSS version mismatch.

**Fix**: Bump `elementor_css_version` and delete `_elementor_css` postmeta:
```bash
python scripts/restoration/wp-elementor-fix.py --config config/config.yaml
```

---

### Global colours/fonts reset to defaults
**Cause**: Elementor Kit post was deleted or its postmeta was cleared.

**Diagnosis**:
```sql
SELECT option_value FROM wp_options WHERE option_name='elementor_active_kit';
-- Should return a post_id. Then:
SELECT * FROM wp_postmeta WHERE post_id=KIT_ID AND meta_key='_elementor_page_settings';
```

**Fix**: Restore Kit settings from backup. If no backup, reconfigure in
Elementor → Site Settings → Global Colours + Global Fonts.

---

### Theme Builder header/footer missing (Pro)
**Cause**: Elementor Pro plugin deleted or `elementor-pro/elementor-pro.php`
removed from `active_plugins`.

**Fix**: Re-install Elementor Pro from your Elementor account → My Subscriptions → Downloads.
Then re-run `wp-elementor-fix.py`.

---

### Editor loads but changes don't save
**Cause**: Nonce issue (WP session expired), DB write permissions, or
PHP memory limit too low.

**Diagnosis**:
```bash
# Check PHP memory limit
ssh USER@HOST "php -r 'echo ini_get(\"memory_limit\");'"
# Check for DB errors
ssh USER@HOST "tail -50 /path/to/wp-content/debug.log"
```

## Recommended Theme Pairings

| Theme | Notes |
|-------|-------|
| **Hello Elementor** | Elementor's own lightweight theme. Purpose-built, zero styling conflicts. Use with Elementor Pro Theme Builder. |
| **Kadence** | Excellent pairing — Kadence global styles complement Elementor's kit. Use Kadence for headers/footers, Elementor for page content. |
| **Astra** | Performance-focused, good Elementor compatibility. |
| **GeneratePress** | Ultra-lightweight, great for speed. |
| **OceanWP** | Full-featured, many Elementor extensions. |

## Elementor CSS Selector Patterns

```css
/* Section */
.elementor-section { }
.elementor-section.elementor-section-full_width { }

/* Column */
.elementor-column { }

/* Widget container */
.elementor-widget { }
.elementor-widget-text-editor { }
.elementor-widget-heading { }
.elementor-widget-image { }
.elementor-widget-button { }

/* Inner section (nested) */
.elementor-inner-section { }

/* Target by Elementor CSS ID (set in Advanced tab) */
#my-section { }

/* Target by CSS class (set in Advanced tab) */
.my-custom-class { }
```

## Debug Mode

Enable temporarily for diagnosis (never leave on in production):

```php
// wp-config.php
define( 'ELEMENTOR_DEBUG', true );
```

Or via SSH:
```bash
python scripts/hardening/wp-harden.py --config config/config.yaml --dry-run
# Check what WP_DEBUG state the script would set
```
