#!/usr/bin/env python3
"""
wp-plugin-restore.py — Restore deleted WordPress plugins
=========================================================
Restores plugins from two sources (tried in order):
  1. Same-server sibling site (instant cp -ra, no download needed)
  2. WordPress.org API download

Then reactivates them in the DB if --activate flag is given.

Use this after an attack where an attacker
deleted all 10 plugins from wp-content/plugins/.

Usage:
  python wp-plugin-restore.py \\
      --host HOST --user USER --password PASS --wp-path /path/to/wp \\
      --db-host DBHOST --db-user DBUSER --db-pass DBPASS --db-name DBNAME \\
      --db-prefix wp_ \\
      --plugins elementor,cloudflare,rank-math \\
      [--sibling-plugins-path /path/to/sibling/wp-content/plugins] \\
      [--activate] [--dry-run]
"""

import argparse
import json
import re
import shlex
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
from wp_connect import (
    WPConnection, add_connection_args, print_banner, AuditResult,
    ok, warn, err, info, section
)

_SLUG_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]*$')


def _validate_slug(slug: str) -> str:
    """Raise ValueError if slug contains path-traversal or shell-unsafe characters."""
    if not _SLUG_RE.match(slug):
        raise ValueError(f"Invalid plugin slug {slug!r} — must match [A-Za-z0-9._-]+")
    return slug


def _php_str(value: str) -> str:
    """Escape value for safe embedding inside a PHP single-quoted string literal."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


# Canonical wordpress.org slugs for common plugins
WP_ORG_SLUGS = {
    "elementor":                "elementor",
    "cloudflare":               "cloudflare",
    "rank-math":                "seo-by-rank-math",
    "seo-by-rank-math":        "seo-by-rank-math",
    "header-footer-elementor":  "header-footer-elementor",
    "kadence-starter-templates":"kadence-starter-templates",
    "imagify":                  "imagify",
    "imagemagick-engine":       "imagemagick-engine",
    "insert-headers-and-footers":"insert-headers-and-footers",
    "auto-sizes":               "auto-sizes",
    "wanimations_img":          "wanimations-image-reveal-on-scroll",
    "contact-form-7":           "contact-form-7",
    "wordfence":                "wordfence",
    "really-simple-ssl":        "really-simple-ssl",
    "updraftplus":              "updraftplus",
    "wp-super-cache":           "wp-super-cache",
}


def restore_from_sibling(wp: WPConnection, slug: str, sibling_path: str) -> bool:
    """Copy plugin from sibling WP installation on same server."""
    src = f"{sibling_path}/{slug}"
    dst = wp.wp(f"wp-content/plugins/{slug}")
    exists = wp.ssh(f"test -d {shlex.quote(src)} && echo Y || echo N")
    if exists != "Y":
        return False
    out = wp.ssh(f"cp -ra {shlex.quote(src)} {shlex.quote(dst)} && echo OK || echo FAIL")
    return "OK" in out


def restore_from_wporg(wp: WPConnection, slug: str) -> bool:
    """Download and install plugin from wordpress.org API."""
    canonical = WP_ORG_SLUGS.get(slug, slug)
    tmp_zip = f"/tmp/{canonical}.zip"
    tmp_dir = f"/tmp/wp-plugin-{canonical}"
    plugins_dir = wp.wp("wp-content/plugins")

    # Get latest version via API
    api_url = f"https://api.wordpress.org/plugins/info/1.0/{canonical}.json"
    version = wp.ssh(
        f"curl -s {shlex.quote(api_url)} 2>/dev/null | "
        f"python3 -c \"import sys,json; d=json.load(sys.stdin); print(d.get('version',''))\" "
        f"2>/dev/null"
    )
    if not version.strip():
        warn(f"  Cannot get version for {canonical} from wordpress.org API")
        # Try direct latest download URL
        dl_url = f"https://downloads.wordpress.org/plugin/{canonical}.latest-stable.zip"
    else:
        dl_url = f"https://downloads.wordpress.org/plugin/{canonical}.{version.strip()}.zip"

    info(f"  Downloading {canonical} from wordpress.org...")
    download = wp.ssh(
        f"wget -q -O {shlex.quote(tmp_zip)} {shlex.quote(dl_url)} 2>/dev/null && echo OK || echo FAIL",
        timeout=120
    )
    if "FAIL" in download or "OK" not in download:
        return False

    # Unzip to plugins dir — target the canonical subdirectory by name so
    # flat zips (no top-level subdir) don't scatter files across plugins/.
    plugin_src = shlex.quote(tmp_dir + "/" + canonical)
    plugin_dst = shlex.quote(plugins_dir + "/" + canonical)
    unzip = wp.ssh(
        f"unzip -q {shlex.quote(tmp_zip)} -d {shlex.quote(tmp_dir)} 2>/dev/null && "
        f"mv {plugin_src} {plugin_dst} 2>/dev/null && "
        f"rm -rf {shlex.quote(tmp_zip)} {shlex.quote(tmp_dir)} && echo OK || echo FAIL",
        timeout=60
    )
    return "OK" in unzip


def activate_plugin(wp: WPConnection, slug: str) -> bool:
    """Add plugin to active_plugins in the DB."""
    p = wp.db_prefix
    # Find the main plugin file
    main_file = wp.ssh(
        f"find {shlex.quote(wp.wp(f'wp-content/plugins/{slug}'))} "
        f"-maxdepth 1 -name '*.php' 2>/dev/null | head -1"
    )
    if not main_file.strip():
        return False

    # Extract just plugin-dir/file.php
    parts = main_file.strip().split("/wp-content/plugins/")
    if len(parts) < 2:
        return False
    rel_path = parts[1].strip()
    path_len = len(rel_path)

    # Check if already in active_plugins — use LOCATE (not LIKE) to avoid
    # % and _ acting as wildcards in plugin paths like rank_math/rank_math.php.
    safe_rel = WPConnection.sql_escape(rel_path)
    already = wp.db(
        f"SELECT COUNT(*) FROM {p}options "
        f"WHERE option_name='active_plugins' AND LOCATE('{safe_rel}', option_value) > 0;"
    )
    if already.strip() and already.strip() != "0":
        info(f"  {slug} already in active_plugins")
        return True

    # Activate via a PHP script run over SSH CLI. Written to /tmp (not docroot)
    # so it is never web-accessible. Both wp_path and rel_path are escaped for
    # PHP single-quoted string literals before interpolation.
    safe_wp_path = _php_str(wp.wp_path)
    safe_rel_php = _php_str(rel_path)
    php_activate = f"""<?php
define('ABSPATH', '{safe_wp_path}/');
require_once('{safe_wp_path}/wp-load.php');
$plugins = get_option('active_plugins', array());
if (!in_array('{safe_rel_php}', $plugins)) {{
    $plugins[] = '{safe_rel_php}';
    update_option('active_plugins', $plugins);
    echo 'ACTIVATED';
}} else {{
    echo 'ALREADY_ACTIVE';
}}
"""
    probe_path = f"/tmp/wpa-activate-{wp.db_prefix}{slug}.php"
    wp.sftp_write(probe_path, php_activate.encode())
    wp.ssh(f"chmod 600 {shlex.quote(probe_path)}")
    result = wp.ssh(f"php {shlex.quote(probe_path)} 2>/dev/null")
    wp.ssh(f"rm -f {shlex.quote(probe_path)}")
    return "ACTIVATED" in result or "ALREADY_ACTIVE" in result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WP-Arsenal: Restore deleted WordPress plugins",
    )
    add_connection_args(parser)
    parser.add_argument("--plugins", required=True,
                        help="Comma-separated plugin slugs to restore")
    parser.add_argument("--sibling-plugins-path", dest="sibling_path", default="",
                        help="Path to plugins/ directory of a sibling WP site on same server")
    parser.add_argument("--activate", action="store_true",
                        help="Reactivate plugins in active_plugins after restoring")
    args = parser.parse_args()

    plugins = [p.strip() for p in args.plugins.split(",") if p.strip()]
    for slug in plugins:
        try:
            _validate_slug(slug)
        except ValueError as exc:
            sys.exit(f"[ERROR] {exc}")

    print_banner(f"WP-PLUGIN-RESTORE — Restoring {len(plugins)} plugin(s)", args.dry_run)

    result = AuditResult("wp-plugin-restore")
    restored = 0
    failed = []

    with WPConnection(args) as wp:
        for slug in plugins:
            section(f"Plugin: {slug}")

            dst = wp.wp(f"wp-content/plugins/{slug}")
            if wp.wp_exists(f"wp-content/plugins/{slug}"):
                ok(f"{slug}: already exists, skipping restore")
                result.add("INFO", "already-exists", slug, dst)
                continue

            if wp.dry_run:
                info(f"[DRY-RUN] Would restore {slug}")
                continue

            success = False

            # Try sibling first
            if args.sibling_path:
                info(f"Trying sibling: {args.sibling_path}/{slug}")
                success = restore_from_sibling(wp, slug, args.sibling_path)
                if success:
                    ok(f"{slug}: restored from sibling")
                    result.add("INFO", "restored-sibling", slug, dst)
                    restored += 1

            # Fall back to wordpress.org
            if not success:
                info(f"Downloading from wordpress.org...")
                success = restore_from_wporg(wp, slug)
                if success:
                    ok(f"{slug}: restored from wordpress.org")
                    result.add("INFO", "restored-wporg", slug, dst)
                    restored += 1

            if not success:
                err(f"{slug}: FAILED to restore")
                result.add("HIGH", "restore-failed", f"Could not restore {slug}", dst)
                failed.append(slug)
                continue

            # Activate if requested
            if args.activate and success:
                if activate_plugin(wp, slug):
                    ok(f"{slug}: activated")
                    result.add("INFO", "activated", slug, dst)
                else:
                    warn(f"{slug}: could not auto-activate — activate via WP Admin")

    result.stat("restored", restored)
    result.stat("failed", len(failed))
    if failed:
        result.stat("failed_plugins", ", ".join(failed))

    result.print_summary()

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()
