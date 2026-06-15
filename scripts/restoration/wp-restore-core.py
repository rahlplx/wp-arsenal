#!/usr/bin/env python3
"""
wp-restore-core.py — Restore clean WordPress core files
========================================================
Downloads the specified WP version from wordpress.org and overwrites
all core files (wp-admin/, wp-includes/, root PHP files) using rsync.

Does NOT touch wp-content/ or wp-config.php.

Usage:
  python wp-restore-core.py \\
      --host HOST --user USER --password PASS --wp-path /path/to/wp \\
      [--wp-version 6.5.3] [--dry-run]
"""

import argparse
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
from wp_connect import (
    WPConnection, add_connection_args, print_banner, AuditResult,
    ok, warn, err, info, section
)


def get_latest_wp_version(wp: WPConnection) -> str:
    """Query wordpress.org API for current stable version."""
    version = wp.ssh(
        "curl -s 'https://api.wordpress.org/core/version-check/1.7/' 2>/dev/null | "
        "python3 -c \"import sys,json; d=json.load(sys.stdin); "
        "print(d['offers'][0]['version'])\" 2>/dev/null"
    )
    return version.strip() or "6.5.3"


def restore_core(wp: WPConnection, args: argparse.Namespace) -> AuditResult:
    result = AuditResult("wp-restore-core")
    tmp_dir = "/tmp/wp-core-restore"

    # ── Detect WP version ──────────────────────────────────────────────
    section("1. Determine WP version")
    if args.wp_version:
        version = args.wp_version
        info(f"Using specified version: {version}")
    else:
        version = get_latest_wp_version(wp)
        info(f"Latest stable version: {version}")

    result.stat("wp_version", version)
    dl_url = f"https://wordpress.org/wordpress-{version}.tar.gz"

    # ── Download ───────────────────────────────────────────────────────
    section("2. Download WordPress")
    tar_path = f"{tmp_dir}/wordpress-{version}.tar.gz"

    if wp.dry_run:
        info(f"[DRY-RUN] Would download {dl_url}")
        return result

    prep = wp.ssh(f"mkdir -p '{tmp_dir}' && echo OK")
    if "OK" not in prep:
        err(f"Cannot create temp directory {tmp_dir}")
        result.add("CRITICAL", "setup-failed", "Cannot create temp dir", tmp_dir)
        return result

    info(f"Downloading {dl_url}...")
    dl = wp.ssh(
        f"wget -q -O '{tar_path}' '{dl_url}' 2>/dev/null && echo OK || echo FAIL",
        timeout=300
    )
    if "FAIL" in dl or "OK" not in dl:
        err("Download failed")
        result.add("CRITICAL", "download-failed", f"Failed to download WordPress {version}", dl_url)
        return result
    ok(f"Downloaded WordPress {version}")

    # ── Extract ────────────────────────────────────────────────────────
    section("3. Extract")
    extract = wp.ssh(
        f"tar -xzf '{tar_path}' -C '{tmp_dir}/' 2>/dev/null && echo OK || echo FAIL"
    )
    if "FAIL" in extract or "OK" not in extract:
        err("Extract failed")
        result.add("CRITICAL", "extract-failed", "tar extraction failed", tar_path)
        return result
    ok("Extracted")

    # ── rsync core files ───────────────────────────────────────────────
    section("4. Sync core files (exclude wp-content, wp-config.php)")
    src = f"{tmp_dir}/wordpress/"

    rsync_cmd = (
        f"rsync -a --delete "
        f"--exclude='wp-content/' "
        f"--exclude='wp-config.php' "
        f"--exclude='wp-config-sample.php' "
        f"'{src}' '{wp.wp_path}/' "
        f"&& echo OK || echo FAIL"
    )
    sync = wp.ssh(rsync_cmd, timeout=300)
    if "FAIL" in sync or "OK" not in sync:
        err("rsync failed")
        result.add("CRITICAL", "sync-failed", "rsync core files failed", wp.wp_path)
        return result
    ok(f"Core files synced from WordPress {version}")
    result.add("INFO", "restored", f"WordPress {version} core files synced", wp.wp_path)

    # ── Fix permissions ────────────────────────────────────────────────
    section("5. Fix permissions")
    wp.ssh(f"find '{wp.wp_path}' -type d -exec chmod 755 {{}} \\; 2>/dev/null")
    wp.ssh(f"find '{wp.wp_path}' -name '*.php' -exec chmod 644 {{}} \\; 2>/dev/null")
    wp.ssh(f"chmod 600 '{wp.wp('wp-config.php')}' 2>/dev/null")
    ok("Permissions fixed")

    # ── Cleanup ────────────────────────────────────────────────────────
    section("6. Cleanup temp files")
    wp.ssh(f"rm -rf '{tmp_dir}'")
    ok("Temp files removed")

    result.stat("status", "success")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WP-Arsenal: Restore clean WordPress core files",
    )
    add_connection_args(parser)
    parser.add_argument("--wp-version", dest="wp_version", default="",
                        help="WordPress version to restore (default: latest stable)")
    args = parser.parse_args()

    print_banner("WP-RESTORE-CORE — Restore Clean WordPress Core", args.dry_run)

    with WPConnection(args) as wp:
        result = restore_core(wp, args)

    result.print_summary()

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()
