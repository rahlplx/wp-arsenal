---
name: kadence-theme-guide
description: >
  Comprehensive guide to building and recovering Kadence-based WordPress sites.
  Covers global styles, Kadence Blocks, Header/Footer builder, template library,
  child theme best practices, and post-attack recovery sequences.
triggers:
  - Kadence
  - Kadence theme
  - Kadence blocks
  - Kadence header builder
  - Kadence global styles
  - Kadence recovery
---

# Kadence Theme Guide

Kadence is a lightweight, performant WordPress theme with built-in block support,
a full-site header/footer builder, and deep Kadence Blocks integration.

## File Structure

```
wp-content/themes/kadence/
├── style.css              ← Theme metadata + version
├── functions.php          ← Core functionality
├── header.php             ← Template header (minimal — Kadence uses block header)
├── footer.php             ← Template footer
├── inc/
│   ├── customizer/        ← All Customizer settings
│   ├── blocks/            ← Kadence Blocks integration
│   └── template-parts/    ← Reusable template fragments
└── assets/
    ├── css/               ← Theme CSS (compiled)
    └── js/                ← Theme JS

wp-content/themes/kadence-child/    ← Your child theme (always use a child)
├── style.css              ← /* Template: kadence */
├── functions.php          ← Enqueue parent + add hooks
└── [override files]       ← Any file from parent can be overridden here
```

## Global Colours and Typography

Set in **Appearance → Customise → Global Colours** and **Global Typography**.
These generate CSS custom properties:

```css
:root {
    --global-palette1: #3182CE;   /* Primary */
    --global-palette2: #2B6CB0;   /* Primary dark */
    --global-palette3: #1A202C;   /* Heading colour */
    --global-palette4: #2D3748;   /* Body colour */
    --global-palette5: #4A5568;   /* Subtle text */
    --global-palette6: #718096;   /* Light text */
    --global-palette7: #EDF2F7;   /* Background light */
    --global-palette8: #F7FAFC;   /* Background very light */
    --global-palette9: #FFFFFF;   /* White */
}
```

Override these in your child theme's `style.css` to change the palette globally:

```css
:root {
    --global-palette1: #E53E3E;   /* Change primary to red */
}
```

## Kadence Blocks

Installed as a plugin (`kadence-blocks`). Core blocks available free:

| Block | Use |
|-------|-----|
| Row Layout | Multi-column layouts with full control |
| Advanced Heading | Custom typography per heading |
| Advanced Button | Button groups, hover effects |
| Info Box | Icon + text cards |
| Tabs | Tabbed content sections |
| Accordion | FAQ-style expandable content |
| Form | Contact forms with basic spam protection |
| Advanced Gallery | Masonry, carousel, grid galleries |

**Kadence Blocks Pro** adds: Slider, Portfolio, Posts Grid, WooCommerce blocks.

### Kadence Blocks CSS selectors

```css
/* Row Layout container */
.kadence-column { }

/* Advanced Heading */
.wp-block-kadence-advancedheading { }

/* Info Box */
.wp-block-kadence-infobox { }

/* Tab container */
.kt-tabs-wrap { }

/* Accordion */
.kt-accordion-panel { }
```

## Header/Footer Builder

Kadence has a drag-drop header and footer builder in the Customiser:
**Appearance → Customise → Header Builder / Footer Builder**

Layout zones:
- **Top bar**: 3 columns (left/centre/right)
- **Main header**: 3 columns
- **Bottom bar**: 3 columns
- **Footer**: 1–6 columns

Available elements: Logo, Navigation, Button, HTML, Social, Search,
Cart, Off-Canvas, Divider.

### Override header for specific page (PHP)

```php
// functions.php in child theme
add_filter( 'kadence_header_layout', function( $layout ) {
    if ( is_page( 'landing-page' ) ) {
        return 'minimal'; // or a custom layout slug
    }
    return $layout;
} );
```

## Post-Attack Recovery Sequence

If the Kadence theme is broken after an attack:

```bash
# 1. Check theme exists on filesystem
python scripts/security/wp-scan.py --config config/config.yaml

# 2. Audit theme files for injections
python scripts/security/wp-theme-audit.py --config config/config.yaml --theme kadence

# 3. If theme is infected — switch to safe theme first
python scripts/management/wp-theme-switch.py --config config/config.yaml \
    --activate twentytwentyfour

# 4. Reinstall Kadence from wordpress.org
python scripts/restoration/wp-plugin-restore.py --config config/config.yaml \
    --plugins kadence

# 5. Fix Elementor if used alongside Kadence
python scripts/restoration/wp-elementor-fix.py --config config/config.yaml

# 6. Switch back to Kadence
python scripts/management/wp-theme-switch.py --config config/config.yaml \
    --activate kadence

# 7. Reaudit
python scripts/security/wp-theme-audit.py --config config/config.yaml --theme kadence
```

## Customiser Settings Recovery

Kadence stores all Customiser settings in `wp_options` as `theme_mods_kadence`.
This serialized value can be exported/imported:

```bash
# Export via SSH
mysql -u USER -pPASS DB -e \
    "SELECT option_value FROM wp_options WHERE option_name='theme_mods_kadence';" \
    > kadence-mods-backup.txt

# Import
mysql -u USER -pPASS DB -e \
    "UPDATE wp_options SET option_value='PASTE_SERIALIZED_VALUE' \
    WHERE option_name='theme_mods_kadence';"
```

## Performance Tips

- Enable **Lazy Load** in Kadence settings
- Use **Kadence Blocks** Row Layout instead of shortcodes for better output
- Set **Kadence → Performance → Remove Kadence CSS for non-Kadence pages**
- Use child theme for any CSS overrides — never edit parent theme files

## Common CSS Targets

```css
/* Site header */
#masthead { }

/* Navigation */
#site-navigation { }
nav.kadence-navigation { }

/* Hero/Banner */
.kadence-hero { }

/* Footer */
#colophon { }

/* Page content area */
.entry-content { }

/* WooCommerce product grid */
ul.products li.product { }
```
