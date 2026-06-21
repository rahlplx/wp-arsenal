#!/usr/bin/env python3
"""
wp-elementor-fix.py — Fix broken Elementor rendering
=====================================================
Resolves the most common Elementor rendering failures:
  1. Bumps elementor_css_version to force CSS regeneration
  2. Clears _elementor_css post meta cache
  3. Removes stale transients
  4. Verifies active_plugins doesn't list any missing files
  5. Checks Elementor kit (global styles) is intact

Used after malware cleanup or plugin restore to bring back
Elementor-rendered layouts.

Usage:
  python wp-elementor-fix.py \\
      --host HOST --user USER --password PASS --wp-path /path/to/wp \\
      --db-host DBHOST --db-user DBUSER --db-pass DBPASS --db-name DBNAME \\
      --db-prefix wp_ [--dry-run]
"""

import argparse
import json
import shlex
import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
from wp_connect import (
    WPConnection, add_connection_args, print_banner, AuditResult,
    ok, warn, err, info, section
)


def fix_elementor(wp: WPConnection, args: argparse.Namespace) -> AuditResult:
    result = AuditResult("wp-elementor-fix")
    p = wp.db_prefix

    # ── 1. Verify Elementor plugin exists ─────────────────────────────
    section("1. Elementor plugin filesystem check")
    elementor_dir = wp.wp("wp-content/plugins/elementor")
    elementor_pro_dir = wp.wp("wp-content/plugins/elementor-pro")

    el_exists = wp.wp_exists("wp-content/plugins/elementor")
    el_pro_exists = wp.wp_exists("wp-content/plugins/elementor-pro")

    if el_exists:
        ok("Elementor (free) plugin directory exists")
    else:
        err("Elementor plugin MISSING from filesystem — cannot fix without restoring it first")
        result.add("CRITICAL", "plugin-missing", "Elementor directory not found", elementor_dir)
        return result

    if el_pro_exists:
        ok("Elementor Pro directory exists")
    else:
        warn("Elementor Pro directory missing — will remove from active_plugins")
        result.add("HIGH", "pro-missing", "Elementor Pro missing from filesystem", elementor_pro_dir)

    # ── 2. Fix active_plugins — remove any missing plugin ─────────────
    section("2. Clean active_plugins of missing entries")
    active_raw = wp.db(
        f"SELECT option_value FROM {p}options WHERE option_name='active_plugins' LIMIT 1;"
    )
    if active_raw:
        plugins_in_db = active_raw.replace("option_value", "").strip()
        info(f"Active plugins in DB:\n{plugins_in_db[:300]}")

        # Check elementor-pro specifically
        if "elementor-pro" in plugins_in_db and not el_pro_exists:
            warn("Removing elementor-pro from active_plugins (file missing)")
            if not wp.dry_run:
                wp.db_write(
                    f"UPDATE {p}options "
                    f"SET option_value = REPLACE(option_value, "
                    f"'s:39:\"elementor-pro/elementor-pro.php\";', '') "
                    f"WHERE option_name = 'active_plugins';"
                )
                ok("Removed elementor-pro from active_plugins")
                result.add("INFO", "fixed", "Removed missing elementor-pro from active_plugins", "")

    # ── 3. Bump elementor_css_version to force regeneration ───────────
    section("3. Bump Elementor CSS version")
    new_ver = str(int(time.time()))
    if wp.dry_run:
        info(f"[DRY-RUN] Would set elementor_css_version = {new_ver}")
    else:
        wp.db_write(
            f"UPDATE {p}options SET option_value='{new_ver}' "
            f"WHERE option_name='elementor_css_version';"
        )
        ok(f"Set elementor_css_version = {new_ver}")
        result.add("INFO", "fixed", f"Bumped elementor_css_version to {new_ver}", "")

    # ── 4. Clear _elementor_css post meta (forces rebuild per-page) ───
    section("4. Clear _elementor_css post meta")
    if wp.dry_run:
        count = wp.db(f"SELECT COUNT(*) FROM {p}postmeta WHERE meta_key='_elementor_css';")
        info(f"[DRY-RUN] Would delete {count.strip()} _elementor_css rows")
    else:
        wp.db_write(f"DELETE FROM {p}postmeta WHERE meta_key='_elementor_css';")
        ok("Cleared _elementor_css post meta")
        result.add("INFO", "fixed", "Cleared _elementor_css post meta", "")

    # ── 5. Clear Elementor transients ─────────────────────────────────
    section("5. Clear Elementor transients")
    if wp.dry_run:
        count = wp.db(
            f"SELECT COUNT(*) FROM {p}options "
            f"WHERE option_name LIKE '_transient_elementor%' "
            f"OR option_name LIKE '_transient_timeout_elementor%';"
        )
        info(f"[DRY-RUN] Would delete {count.strip()} elementor transients")
    else:
        wp.db_write(
            f"DELETE FROM {p}options "
            f"WHERE option_name LIKE '_transient_elementor%' "
            f"OR option_name LIKE '_transient_timeout_elementor%';"
        )
        ok("Cleared Elementor transients")
        result.add("INFO", "fixed", "Cleared Elementor transients", "")

    # ── 6. Clear all WP transients (belt-and-suspenders) ──────────────
    section("6. Clear all WP transients")
    if not wp.dry_run:
        wp.db_write(
            f"DELETE FROM {p}options "
            f"WHERE option_name LIKE '_transient_%' "
            f"OR option_name LIKE '_site_transient_%';"
        )
        ok("Cleared all WP transients")

    # ── 7. Clear wp-content/cache/ ────────────────────────────────────
    section("7. Clear file cache")
    cache_dir = wp.wp("wp-content/cache")
    if wp.wp_exists("wp-content/cache"):
        if wp.dry_run:
            info("[DRY-RUN] Would clear wp-content/cache/")
        else:
            wp.ssh(f"find {shlex.quote(cache_dir)} -mindepth 1 -delete 2>/dev/null || true")
            ok("Cleared wp-content/cache/")
    else:
        info("No wp-content/cache/ directory")

    # ── 8. Verify Elementor kit (global styles) ───────────────────────
    section("8. Elementor kit integrity")
    kit_row = wp.db(
        f"SELECT post_id FROM {p}postmeta "
        f"WHERE meta_key='_elementor_template_type' AND meta_value='kit' LIMIT 1;"
    )
    if kit_row and kit_row.strip():
        ok(f"Elementor kit found (post_id {kit_row.strip()})")
        result.stat("elementor_kit_id", kit_row.strip())
    else:
        warn("No Elementor kit found — global styles may not apply")
        result.add("MEDIUM", "kit-missing", "Elementor kit not found in DB", "")

    # ── 9. Verify siteurl/home consistency ────────────────────────────
    section("9. siteurl / home consistency")
    siteurl = wp.db(f"SELECT option_value FROM {p}options WHERE option_name='siteurl';")
    home    = wp.db(f"SELECT option_value FROM {p}options WHERE option_name='home';")
    info(f"siteurl: {siteurl.strip()}")
    info(f"home:    {home.strip()}")
    if siteurl.strip() != home.strip():
        warn("siteurl and home are different — may cause mixed-content issues")
        result.add("MEDIUM", "url-mismatch", f"siteurl≠home: {siteurl.strip()} vs {home.strip()}", "")

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WP-Arsenal: Fix broken Elementor rendering",
    )
    add_connection_args(parser)
    args = parser.parse_args()

    print_banner("WP-ELEMENTOR-FIX — Restore Elementor Rendering", args.dry_run)

    with WPConnection(args) as wp:
        result = fix_elementor(wp, args)

    result.print_summary()

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()
