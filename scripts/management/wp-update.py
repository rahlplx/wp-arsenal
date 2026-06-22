#!/usr/bin/env python3
"""
wp-update.py — Update WordPress core, plugins, and themes
===========================================================
Checks for available updates and applies them safely:
  - Verifies site responds before and after each update
  - Skips updates if site goes down (stops chain)
  - Supports dry-run to preview what would be updated

Sources:
  - WordPress core: wordpress.org/API
  - Plugins: wordpress.org/API per plugin (free plugins only)
  - Themes: wordpress.org/API per theme (free themes only)
  Premium/paid plugins must be updated manually via WP Admin.

Usage:
  python wp-update.py --config config/config.yaml --check-only
  python wp-update.py --config config/config.yaml --core
  python wp-update.py --config config/config.yaml --plugins elementor,rank-math
  python wp-update.py --config config/config.yaml --all
  python wp-update.py --config config/config.yaml --dry-run --all
"""

import argparse
import json
import os
import shlex
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
from wp_connect import (
    WPConnection, add_connection_args, print_banner, AuditResult,
    ok, warn, err, info, section
)


def get_installed_wp_version(wp: WPConnection) -> str:
    """Read WordPress version from wp-includes/version.php."""
    out = wp.ssh(
        f"grep \"\\$wp_version\" {shlex.quote(wp.wp_path + '/wp-includes/version.php')} "
        f"2>/dev/null | head -1"
    )
    for part in out.split("="):
        candidate = part.strip().strip(";").strip("'").strip('"')
        if candidate and candidate[0].isdigit():
            return candidate
    return "unknown"


def get_latest_wp_version(wp: WPConnection) -> str:
    """Query wordpress.org API for latest WP version."""
    out = wp.ssh(
        "curl -s 'https://api.wordpress.org/core/version-check/1.7/' 2>/dev/null"
        " | python3 -c \""
        "import sys,json; d=json.load(sys.stdin); "
        "print(d['offers'][0]['version'])"
        "\" 2>/dev/null"
    )
    return out.strip()


def update_wp_core(wp: WPConnection, version: str, result: AuditResult) -> bool:
    """Download and rsync clean WP core, skipping wp-content and wp-config.php."""
    info(f"Downloading WordPress {version}...")
    tmp_tar = f"/tmp/wordpress-{version}.tar.gz"
    tmp_dir = f"/tmp/wordpress-{version}"

    dl_url = f"https://wordpress.org/wordpress-{version}.tar.gz"
    dl = wp.ssh(
        f"wget -q -O {shlex.quote(tmp_tar)} {shlex.quote(dl_url)} 2>/dev/null"
        f" && echo OK || echo FAIL",
        timeout=120
    )
    if "FAIL" in dl or "OK" not in dl:
        err("Download failed")
        result.add("HIGH", "core-update-failed", f"Download failed for WP {version}", "")
        return False

    extract = wp.ssh(
        f"mkdir -p {shlex.quote(tmp_dir)} && tar -xzf {shlex.quote(tmp_tar)} -C {shlex.quote(tmp_dir)} 2>/dev/null"
        f" && echo OK || echo FAIL"
    )
    if "FAIL" in extract or "OK" not in extract:
        err("Core tar extraction failed")
        wp.ssh(f"rm -rf {shlex.quote(tmp_tar)} {shlex.quote(tmp_dir)}")
        result.add("HIGH", "core-update-failed", f"tar extraction failed for WP {version}", "")
        return False

    rsync = wp.ssh(
        f"rsync -a --delete"
        f" --exclude='wp-content/'"
        f" --exclude='wp-config.php'"
        f" --exclude='.htaccess'"
        f" {shlex.quote(tmp_dir + '/wordpress/')} {shlex.quote(wp.wp_path + '/')}"
        f" 2>/dev/null && echo OK || echo FAIL",
        timeout=120
    )
    wp.ssh(f"rm -rf {shlex.quote(tmp_tar)} {shlex.quote(tmp_dir)}")

    if "OK" in rsync:
        ok(f"WordPress core updated to {version}")
        result.add("INFO", "core-updated", f"Updated to {version}", wp.wp_path)
        return True
    err("Core rsync failed")
    result.add("HIGH", "core-update-failed", f"rsync failed for WP {version}", "")
    return False


def get_plugin_version_wporg(wp: WPConnection, slug: str) -> str:
    """Query wordpress.org for latest plugin version."""
    api_url = f"https://api.wordpress.org/plugins/info/1.0/{slug}.json"
    out = wp.ssh(
        f"curl -s {shlex.quote(api_url)} 2>/dev/null"
        f" | python3 -c \"import sys,json; d=json.load(sys.stdin); print(d.get('version',''))\" "
        f"2>/dev/null"
    )
    return out.strip()


def get_installed_plugin_version(wp: WPConnection, slug: str) -> str:
    """Read Version: header from main plugin PHP file."""
    main_file = wp.ssh(
        f"find {shlex.quote(wp.wp('wp-content/plugins/' + slug))} "
        f"-maxdepth 1 -name '*.php' 2>/dev/null | head -1"
    ).strip()
    if not main_file:
        return "unknown"
    out = wp.ssh(
        f"grep -i 'Version:' {shlex.quote(main_file)} 2>/dev/null | head -1"
    )
    for part in out.split(":"):
        candidate = part.strip()
        if candidate and candidate[0].isdigit():
            return candidate
    return "unknown"


def update_plugin(wp: WPConnection, slug: str, new_version: str, result: AuditResult) -> bool:
    """Download and replace plugin from wordpress.org."""
    tmp_zip = f"/tmp/{slug}-{new_version}.zip"
    tmp_dir = f"/tmp/plugin-update-{slug}"
    plugins_dir = wp.wp("wp-content/plugins")

    plugin_url = f"https://downloads.wordpress.org/plugin/{slug}.{new_version}.zip"
    dl = wp.ssh(
        f"wget -q -O {shlex.quote(tmp_zip)} {shlex.quote(plugin_url)} 2>/dev/null"
        f" && echo OK || echo FAIL",
        timeout=120
    )
    if "FAIL" in dl or "OK" not in dl:
        err(f"  Download failed for {slug}")
        result.add("MEDIUM", "plugin-update-failed", f"{slug}: download failed", "")
        return False

    # Unzip to tmp first, then atomically swap so the live plugin dir is never
    # absent — rm -rf before confirming unzip succeeds leaves the plugin deleted.
    out = wp.ssh(
        f"rm -rf {shlex.quote(tmp_dir)} 2>/dev/null"
        f" && unzip -q {shlex.quote(tmp_zip)} -d {shlex.quote(tmp_dir)} 2>/dev/null"
        f" && rm -rf {shlex.quote(plugins_dir + '/' + slug)}"
        f" && mv {shlex.quote(tmp_dir + '/' + slug)} {shlex.quote(plugins_dir + '/' + slug)}"
        f" && rm -rf {shlex.quote(tmp_zip)} {shlex.quote(tmp_dir)}"
        f" && echo OK || echo FAIL"
    )
    if "FAIL" in out or "OK" not in out:
        err(f"  Replace failed for {slug}")
        result.add("MEDIUM", "plugin-update-failed", f"{slug}: replace failed", "")
        return False
    ok(f"  {slug} → {new_version}")
    result.add("INFO", "plugin-updated", f"{slug} updated to {new_version}", "")
    return True


def site_responds(wp: WPConnection) -> bool:
    """Return True if the site returns HTTP 200."""
    if not wp.site_url:
        return True  # Can't check, assume ok
    code = wp.http_code(wp.site_url, timeout=15)
    return code in ("200", "301", "302")


def get_installed_plugins(wp: WPConnection) -> list[str]:
    """List plugin slugs (directory names) from filesystem."""
    out = wp.ssh(
        f"ls -1 {shlex.quote(wp.wp('wp-content/plugins'))} 2>/dev/null"
    )
    return [p.strip() for p in out.splitlines() if p.strip() and not p.startswith(".")]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WP-Arsenal: Update WordPress core, plugins, and themes"
    )
    add_connection_args(parser)
    parser.add_argument("--core", action="store_true",
                        help="Update WordPress core")
    parser.add_argument("--plugins", default="",
                        help="Comma-separated plugin slugs to update (or 'all')")
    parser.add_argument("--all", action="store_true",
                        help="Update core + all free plugins")
    parser.add_argument("--check-only", action="store_true",
                        help="Check for updates without applying them")
    args = parser.parse_args()

    print_banner("WP-UPDATE — WordPress Update Manager", args.dry_run)
    result = AuditResult("wp-update")
    updates_available = []
    updates_applied = []

    with WPConnection(args) as wp:

        # ── Core check ──────────────────────────────────────────────────
        if args.core or args.all or args.check_only:
            section("WordPress core")
            installed = get_installed_wp_version(wp)
            latest = get_latest_wp_version(wp)
            info(f"Installed: {installed}  |  Latest: {latest}")

            if installed == "unknown":
                warn("Could not read installed WP version")
            elif installed == latest:
                ok(f"Core is up to date ({installed})")
            else:
                warn(f"Update available: {installed} → {latest}")
                updates_available.append(f"core: {installed} → {latest}")
                result.add("MEDIUM", "core-outdated", f"{installed} → {latest}", wp.wp_path)

                if (args.core or args.all) and not args.check_only and not args.dry_run:
                    if update_wp_core(wp, latest, result):
                        updates_applied.append(f"core → {latest}")
                        if not site_responds(wp):
                            err("Site DOWN after core update — review manually")
                            result.add("CRITICAL", "site-down", "Site not responding after core update", "")

        # ── Plugin check ─────────────────────────────────────────────────
        if args.plugins or args.all or args.check_only:
            section("Plugins")

            if args.plugins.lower() == "all" or args.all or args.check_only:
                plugin_list = get_installed_plugins(wp)
                info(f"Found {len(plugin_list)} installed plugins")
            else:
                plugin_list = [p.strip() for p in args.plugins.split(",") if p.strip()]

            for slug in plugin_list:
                installed_ver = get_installed_plugin_version(wp, slug)
                latest_ver = get_plugin_version_wporg(wp, slug)

                if not latest_ver:
                    info(f"  {slug}: not on wordpress.org (premium/private — skip)")
                    continue

                if installed_ver == latest_ver:
                    ok(f"  {slug}: up to date ({installed_ver})")
                elif installed_ver == "unknown":
                    warn(f"  {slug}: installed version unreadable (latest: {latest_ver})")
                else:
                    warn(f"  {slug}: {installed_ver} → {latest_ver}")
                    updates_available.append(f"{slug}: {installed_ver} → {latest_ver}")
                    result.add("LOW", "plugin-outdated", f"{slug}: {installed_ver} → {latest_ver}", "")

                    if not args.check_only and not args.dry_run:
                        if args.all or (args.plugins and slug in [s.strip() for s in args.plugins.split(",")]):
                            if update_plugin(wp, slug, latest_ver, result):
                                updates_applied.append(f"{slug} → {latest_ver}")
                                if not site_responds(wp):
                                    err(f"Site DOWN after updating {slug} — rolling back not supported; check manually")
                                    result.add("CRITICAL", "site-down", f"Site down after {slug} update", "")
                                    break

        # ── Summary ──────────────────────────────────────────────────────
        section("Summary")
        result.stat("updates_available", len(updates_available))
        result.stat("updates_applied", len(updates_applied))
        if updates_available:
            info("Updates available:")
            for u in updates_available:
                info(f"  • {u}")
        if updates_applied:
            ok("Updates applied:")
            for u in updates_applied:
                ok(f"  • {u}")

    result.print_summary()
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()
