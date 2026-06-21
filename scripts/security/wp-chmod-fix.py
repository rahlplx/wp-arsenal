#!/usr/bin/env python3
"""
wp-chmod-fix.py — Fix WordPress file/directory permissions
===========================================================
Enforces correct permissions across the entire WP installation:
  - Directories: 755
  - PHP/config files: 644
  - wp-config.php: 600 (owner-only read)
  - uploads/: 755 dirs, 644 files (no PHP exec)
  - .htaccess: 644

Also detects world-writable files and executable PHP in uploads.

Usage:
  python wp-chmod-fix.py --host HOST --user USER --password PASS \\
      --wp-path /path/to/wp [--dry-run]
"""

import argparse
import json
import shlex
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
from wp_connect import (
    WPConnection, add_connection_args, print_banner, AuditResult,
    ok, warn, err, info, section
)


def fix_permissions(wp: WPConnection, args: argparse.Namespace) -> AuditResult:
    result = AuditResult("wp-chmod-fix")
    fixed = 0

    # ── A. World-writable files (immediate risk) ───────────────────────
    section("A. World-writable files")
    world_writable = wp.ssh(
        f"find {shlex.quote(wp.wp_path)} -perm -o+w -not -path '*/.git/*' 2>/dev/null | head -50"
    )
    ww_list = [p.strip() for p in world_writable.splitlines() if p.strip()]
    if ww_list:
        for path in ww_list:
            err(f"World-writable: {path}")
            result.add("HIGH", "world-writable", "World-writable file", path)
            if not wp.dry_run:
                wp.ssh(f"chmod o-w {shlex.quote(path)}")
                fixed += 1
    else:
        ok("No world-writable files")

    # ── B. Executable PHP files ────────────────────────────────────────
    section("B. PHP files with execute bit set")
    exec_php = wp.ssh(
        f"find {shlex.quote(wp.wp_path)} -name '*.php' -perm /u+x,g+x,o+x 2>/dev/null | head -30"
    )
    exec_list = [p.strip() for p in exec_php.splitlines() if p.strip()]
    if exec_list:
        for path in exec_list:
            warn(f"PHP with exec bit: {path}")
            result.add("MEDIUM", "php-executable", "PHP file has execute bit", path)
            if not wp.dry_run:
                wp.ssh(f"chmod a-x {shlex.quote(path)}")
                fixed += 1
    else:
        ok("No PHP files with execute bit")

    # ── C. Fix directory permissions ───────────────────────────────────
    section("C. Fix directory permissions → 755")
    if wp.dry_run:
        count = wp.ssh(
            f"find {shlex.quote(wp.wp_path)} -type d -not -perm 755 2>/dev/null | wc -l"
        ).strip()
        info(f"[DRY-RUN] Would fix ~{count} directories → chmod 755")
    else:
        wp.ssh(f"find {shlex.quote(wp.wp_path)} -type d -exec chmod 755 {{}} \\; 2>/dev/null")
        ok("All directories set to 755")
        fixed += 1

    # ── D. Fix PHP file permissions ────────────────────────────────────
    section("D. Fix PHP file permissions → 644")
    if wp.dry_run:
        count = wp.ssh(
            f"find {shlex.quote(wp.wp_path)} -name '*.php' -not -perm 644 2>/dev/null | wc -l"
        ).strip()
        info(f"[DRY-RUN] Would fix ~{count} PHP files → chmod 644")
    else:
        wp.ssh(
            f"find {shlex.quote(wp.wp_path)} -name '*.php' -exec chmod 644 {{}} \\; 2>/dev/null"
        )
        ok("All PHP files set to 644")
        fixed += 1

    # ── E. Lock down wp-config.php ─────────────────────────────────────
    section("E. wp-config.php → 600")
    wp_config = wp.wp("wp-config.php")
    if wp.wp_exists("wp-config.php"):
        if wp.dry_run:
            info(f"[DRY-RUN] Would chmod 600 {wp_config}")
        else:
            wp.ssh(f"chmod 600 {shlex.quote(wp_config)}")
            ok(f"wp-config.php locked to 600")
            fixed += 1
    else:
        warn("wp-config.php not found")

    # ── F. Non-PHP files in wp-content/ ───────────────────────────────
    section("F. Non-PHP files in wp-content/ → 644")
    if wp.dry_run:
        info("[DRY-RUN] Would fix non-PHP file permissions in wp-content/")
    else:
        wp.ssh(
            f"find {shlex.quote(wp.wp('wp-content'))} -type f -not -name '*.php' "
            f"-exec chmod 644 {{}} \\; 2>/dev/null"
        )
        ok("Non-PHP files in wp-content/ set to 644")
        fixed += 1

    # ── G. Verify .htaccess permissions ───────────────────────────────
    section("G. .htaccess → 644")
    ht_perm = wp.ssh(f"stat -c '%a' {shlex.quote(wp.wp('.htaccess'))} 2>/dev/null")
    if ht_perm and ht_perm != "644":
        if not wp.dry_run:
            wp.ssh(f"chmod 644 {shlex.quote(wp.wp('.htaccess'))}")
        ok(".htaccess set to 644")
        fixed += 1
    elif ht_perm == "644":
        ok(".htaccess already 644")

    result.stat("items_fixed", fixed)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WP-Arsenal: Fix WordPress file/directory permissions",
    )
    add_connection_args(parser)
    args = parser.parse_args()

    print_banner("WP-CHMOD-FIX — WordPress Permission Hardening", args.dry_run)

    with WPConnection(args) as wp:
        result = fix_permissions(wp, args)

    result.print_summary()

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()
