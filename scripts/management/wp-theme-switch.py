#!/usr/bin/env python3
"""
wp-theme-switch.py — Safely switch WordPress themes via SSH
============================================================
Records the current active theme, switches to the target, and verifies
the site responds. Supports instant rollback to the previous theme.

Usage:
  # Switch to a new theme
  python scripts/management/wp-theme-switch.py --config config/config.yaml \
      --activate twentytwentyfour

  # Preview only (show what would change)
  python scripts/management/wp-theme-switch.py --config config/config.yaml \
      --activate twentytwentyfour --dry-run

  # Rollback to the previous theme
  python scripts/management/wp-theme-switch.py --config config/config.yaml \
      --rollback

  # List available themes
  python scripts/management/wp-theme-switch.py --config config/config.yaml \
      --list
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wp_connect import (
    WPConnection, add_connection_args, print_banner, AuditResult,
    ok, warn, err, info, section
)

PREVIOUS_THEME_OPTION = "wp_arsenal_previous_theme"


def get_current_theme(wp: WPConnection) -> dict:
    """Read current template, stylesheet, and current_theme options."""
    p = wp.db_prefix
    rows = wp.db(
        f"SELECT option_name, option_value FROM {p}options "
        f"WHERE option_name IN ('template', 'stylesheet', 'current_theme') "
        f"ORDER BY option_name;"
    )
    result = {}
    for line in rows.strip().splitlines():
        parts = line.strip().split("\t", 1)
        if len(parts) == 2 and parts[0] not in ("option_name",):
            result[parts[0]] = parts[1]
    return result


def get_theme_display_name(wp: WPConnection, slug: str) -> str:
    """Read Theme Name from theme's style.css."""
    style_css = wp.wp(f"wp-content/themes/{slug}/style.css")
    out = wp.ssh(
        f"grep -m 1 '^Theme Name:' '{style_css}' 2>/dev/null"
    )
    return out.strip().replace("Theme Name:", "").strip() if out.strip() else slug


def set_theme(wp: WPConnection, slug: str, result: AuditResult) -> bool:
    """Update template, stylesheet, and current_theme in DB."""
    p = wp.db_prefix
    slug = WPConnection.sql_slug(slug)
    display_name = get_theme_display_name(wp, slug)
    safe_display_name = WPConnection.sql_escape(display_name)

    if wp.dry_run:
        info(f"[DRY-RUN] Would activate: {slug} ({display_name})")
        return True

    wp.db_write(
        f"UPDATE {p}options SET option_value='{slug}' "
        f"WHERE option_name IN ('template', 'stylesheet');"
    )
    wp.db_write(
        f"UPDATE {p}options SET option_value='{safe_display_name}' "
        f"WHERE option_name='current_theme';"
    )

    # Clear theme-related transients
    wp.db_write(
        f"DELETE FROM {p}options "
        f"WHERE option_name LIKE '_transient_theme_%' "
        f"OR option_name LIKE '_site_transient_theme_%' "
        f"OR option_name LIKE '_transient_switch_themes%';"
    )

    ok(f"Theme activated: {slug} ({display_name})")
    result.add("INFO", "theme-activated", f"Activated: {slug} ({display_name})", "")
    return True


def save_previous_theme(wp: WPConnection, current: dict) -> None:
    """Store current theme slug as the previous-theme option for rollback."""
    p = wp.db_prefix
    slug = current.get("template", "")
    if not slug:
        return
    slug = WPConnection.sql_escape(slug)
    # Upsert
    existing = wp.db(
        f"SELECT COUNT(*) FROM {p}options WHERE option_name='{PREVIOUS_THEME_OPTION}';"
    )
    if existing.strip().splitlines()[-1].strip() == "0":
        wp.db_write(
            f"INSERT INTO {p}options (option_name, option_value, autoload) "
            f"VALUES ('{PREVIOUS_THEME_OPTION}', '{slug}', 'no');"
        )
    else:
        wp.db_write(
            f"UPDATE {p}options SET option_value='{slug}' "
            f"WHERE option_name='{PREVIOUS_THEME_OPTION}';"
        )


def get_previous_theme(wp: WPConnection) -> str:
    p = wp.db_prefix
    row = wp.db(
        f"SELECT option_value FROM {p}options "
        f"WHERE option_name='{PREVIOUS_THEME_OPTION}' LIMIT 1;"
    )
    return row.strip().splitlines()[-1].strip() if row.strip() else ""


def list_themes(wp: WPConnection) -> None:
    """Print all installed themes with active marker."""
    current = get_current_theme(wp)
    active_slug = current.get("template", "")
    out = wp.ssh(
        f"ls -1 '{wp.wp('wp-content/themes')}' 2>/dev/null"
    )
    themes = sorted(t.strip() for t in out.splitlines() if t.strip())
    info(f"\n{'Slug':35} {'Display Name':30} {'Status'}")
    info("─" * 75)
    for slug in themes:
        name = get_theme_display_name(wp, slug)
        status = "← ACTIVE" if slug == active_slug else ""
        info(f"  {slug:33} {name:30} {status}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WP-Arsenal: Safely switch WordPress themes"
    )
    add_connection_args(parser)
    parser.add_argument("--activate", default="",
                        help="Theme slug to activate")
    parser.add_argument("--rollback", action="store_true",
                        help="Roll back to the previous theme")
    parser.add_argument("--list", action="store_true",
                        help="List all installed themes")
    args = parser.parse_args()

    print_banner("WP-THEME-SWITCH — Safe Theme Switcher", args.dry_run)
    result = AuditResult("wp-theme-switch")

    with WPConnection(args) as wp:

        if args.list:
            list_themes(wp)
            return

        if args.rollback:
            section("Rollback to previous theme")
            prev = get_previous_theme(wp)
            if not prev:
                err("No previous theme recorded — cannot rollback")
                err("Run --list to see available themes and --activate to switch manually")
                sys.exit(1)
            if not wp.wp_exists(f"wp-content/themes/{prev}"):
                err(f"Previous theme '{prev}' no longer exists on filesystem")
                sys.exit(1)
            current = get_current_theme(wp)
            info(f"Current theme: {current.get('template', '?')}")
            info(f"Rolling back to: {prev}")
            set_theme(wp, prev, result)
            if wp.site_url and not wp.dry_run:
                code = wp.http_code(wp.site_url, timeout=15)
                if code == 200:
                    ok(f"Site responds HTTP {code} with {prev} active")
                else:
                    err(f"Site returned HTTP {code} after rollback")
            return

        if not args.activate:
            err("Specify --activate THEME_SLUG, --rollback, or --list")
            sys.exit(1)

        target = args.activate

        section("Pre-switch checks")
        current = get_current_theme(wp)
        current_slug = current.get("template", "?")
        info(f"Current theme: {current_slug}")
        info(f"Target theme:  {target}")

        if current_slug == target:
            ok(f"'{target}' is already the active theme — nothing to do")
            return

        if not wp.wp_exists(f"wp-content/themes/{target}"):
            err(f"Target theme '{target}' not found in wp-content/themes/")
            err("Use --list to see installed themes")
            sys.exit(1)

        ok(f"Target theme exists on filesystem")

        # Save current for rollback
        if not wp.dry_run:
            save_previous_theme(wp, current)
            info(f"Previous theme saved for rollback: {current_slug}")

        # Verify site responds before switching
        if wp.site_url:
            before = wp.http_code(wp.site_url, timeout=15)
            info(f"Site HTTP status before switch: {before}")

        section(f"Switching to: {target}")
        set_theme(wp, target, result)

        # Verify site still responds after switching
        if wp.site_url and not wp.dry_run:
            after = wp.http_code(wp.site_url, timeout=15)
            if after == 200:
                ok(f"Site responds HTTP {after} with '{target}' active")
                result.stat("http_after", after)
            else:
                err(f"Site returned HTTP {after} after switch — initiating auto-rollback")
                result.add("CRITICAL", "site-down",
                           f"Site returned HTTP {after} after switching to {target}", "")
                # Auto-rollback
                warn(f"Auto-rolling back to: {current_slug}")
                set_theme(wp, current_slug, result)
                recover = wp.http_code(wp.site_url, timeout=15)
                if recover == 200:
                    ok(f"Rollback successful — site at {current_slug} (HTTP {recover})")
                else:
                    err(f"Rollback also failed (HTTP {recover}) — manual intervention required")

        result.stat("previous_theme", current_slug)
        result.stat("new_theme", target)
        info(f"\nTo rollback: python wp-theme-switch.py --config config/config.yaml --rollback")

    result.print_summary()
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()
