---
name: wp-theme-switch
description: >
  Safely switch WordPress themes via SSH with automatic rollback if the site
  goes down. Records the previous theme for instant rollback. Verifies HTTP 200
  before and after the switch.
triggers:
  - switch theme
  - change theme
  - activate theme
  - rollback theme
  - revert theme
---

# Skill: wp-theme-switch

Switches the active WordPress theme via direct DB update, verifies the site
responds after the switch, and auto-rolls back if it doesn't.

## Usage

```bash
# List all installed themes
python scripts/management/wp-theme-switch.py --config config/config.yaml --list

# Switch to a theme (with site health check)
python scripts/management/wp-theme-switch.py --config config/config.yaml \
    --activate twentytwentyfour

# Preview the switch without making changes
python scripts/management/wp-theme-switch.py --config config/config.yaml \
    --activate mytheme --dry-run

# Rollback to the previous theme
python scripts/management/wp-theme-switch.py --config config/config.yaml \
    --rollback
```

## What happens on switch

1. Records current theme slug as `wp_arsenal_previous_theme` option (for rollback)
2. Verifies target theme directory exists on filesystem
3. Checks site HTTP status before switching
4. Updates `template`, `stylesheet`, and `current_theme` in `wp_options`
5. Clears theme transients
6. Checks site HTTP status after switching
7. If site returns non-200 → **auto-rollback** to previous theme

## Rollback

The previous theme is saved automatically on every switch. To rollback:

```bash
python scripts/management/wp-theme-switch.py --config config/config.yaml --rollback
```

Only one level of rollback is stored. Multiple consecutive switches: rollback
always returns to the theme that was active immediately before the last switch.

## When to use

- **After an attack**: Switch to a clean default theme to eliminate the theme
  as a persistence vector while you audit
- **Before major theme updates**: Switch to a default theme, update, switch back
- **Testing**: Switch to a default theme to isolate plugin vs. theme issues
- **Emergency**: Site is broken — quickly switch to a known-good theme

## Emergency theme recovery without wp-admin

If wp-admin is inaccessible (blank page, infinite redirect, fatal error):

```bash
# Switch to a built-in safe theme
python scripts/management/wp-theme-switch.py --config config/config.yaml \
    --activate twentytwentyfour

# If that doesn't work, restore the theme files first:
python scripts/restoration/wp-restore-core.py --config config/config.yaml
# Then switch again
```
