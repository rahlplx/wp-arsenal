#!/usr/bin/env python3
"""
wp-shell-nuke.py — Remove confirmed malware files from WordPress
================================================================
Deletes known-bad shell files, removes rogue PHP from uploads/,
and optionally wipes attacker-known plugin directories.

ALWAYS run with --dry-run first to preview before deleting.

Usage:
  python wp-shell-nuke.py --host HOST --user USER --password PASS \\
      --wp-path /path/to/wp [--dry-run]
"""

import argparse
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
from wp_connect import (
    WPConnection, add_connection_args, print_banner, AuditResult,
    ok, warn, err, info, section, RED, GREEN, YELLOW
)

# Attacker toolkit filenames known from real-world incidents
KNOWN_BAD_FILES = [
    # Nyx / TFM toolkit (joshan.com incident 2026-06)
    "offline.php", "functions-interpreter.php", "header-repository.php",
    "index-more.php", "footer-class.php",
    # WPOC REST backdoors
    "cache-handler.php", "wp-term-meta.php", "sso.php",
    "site-compat.php", "http-insights.php",
    # Generic shells
    "shell.php", "cmd.php", "up.php", "upload.php", "wso.php",
    "c99.php", "r57.php", "b374k.php", "adminer.php", "filemanager.php",
    "wp-temp.php", "test.php",
    # Extension masquerading
    ".ico.php", ".jpg.php", ".gif.php", ".png.php",
]

# Plugin directories known to be attacker-planted (not from wordpress.org)
ROGUE_PLUGINS = [
    "fileorganizer",     # File manager shell plugin
    "cacheengine",       # DB connection flood / cache bypass
    "wp-file-manager",   # Vulnerable file manager
]


def nuke(wp: WPConnection, args: argparse.Namespace) -> AuditResult:
    result = AuditResult("wp-shell-nuke")
    deleted = 0
    skipped = 0

    # ── A. Search and delete known-bad filenames ───────────────────────
    section("A. Remove known-bad filenames")
    for fname in KNOWN_BAD_FILES:
        hits = wp.ssh(
            f"find '{wp.wp_path}' -name '{fname}' "
            f"-not -path '*/node_modules/*' 2>/dev/null"
        )
        for path in [p.strip() for p in hits.splitlines() if p.strip()]:
            if wp.dry_run:
                warn(f"[DRY-RUN] Would delete: {path}")
                result.add("INFO", "would-delete", fname, path)
            else:
                out = wp.ssh(f"rm -f '{path}' && echo DELETED || echo FAILED")
                if "DELETED" in out:
                    ok(f"Deleted: {path}")
                    result.add("INFO", "deleted", fname, path)
                    deleted += 1
                else:
                    err(f"Failed to delete: {path}")
                    result.add("HIGH", "delete-failed", fname, path)

    # ── B. Remove PHP files from uploads/ ──────────────────────────────
    section("B. Remove PHP files from uploads/")
    uploads_path = wp.wp("wp-content/uploads")
    php_in_uploads = wp.ssh(
        f"find '{uploads_path}' -name '*.php' 2>/dev/null"
    )
    for path in [p.strip() for p in php_in_uploads.splitlines() if p.strip()]:
        if wp.dry_run:
            warn(f"[DRY-RUN] Would delete PHP from uploads: {path}")
            result.add("INFO", "would-delete-upload-php", "php-in-uploads", path)
        else:
            out = wp.ssh(f"rm -f '{path}' && echo DELETED || echo FAILED")
            if "DELETED" in out:
                ok(f"Deleted upload PHP: {path}")
                result.add("INFO", "deleted-upload-php", "php-in-uploads", path)
                deleted += 1
            else:
                err(f"Failed to delete: {path}")
                result.add("HIGH", "delete-failed", "php-in-uploads", path)

    # ── C. Block PHP execution in uploads/ ─────────────────────────────
    section("C. Block PHP execution in uploads/")
    htaccess_content = b"<Files *.php>\ndeny from all\n</Files>\n"
    ht_path = f"{uploads_path}/.htaccess"
    existing = wp.sftp_read(ht_path)
    if b"deny from all" in existing:
        ok("uploads/.htaccess already blocks PHP")
    else:
        if wp.sftp_write(ht_path, htaccess_content):
            ok("Wrote PHP-blocking .htaccess to uploads/")
            result.add("INFO", "hardened", "PHP execution blocked in uploads", ht_path)
        else:
            err("Could not write uploads/.htaccess")

    # ── D. Remove rogue plugins ─────────────────────────────────────────
    section("D. Remove rogue plugins")
    plugins_path = wp.wp("wp-content/plugins")
    for plugin in ROGUE_PLUGINS:
        plugin_dir = f"{plugins_path}/{plugin}"
        exists = wp.ssh(f"test -d '{plugin_dir}' && echo Y || echo N")
        if exists == "Y":
            if wp.dry_run:
                warn(f"[DRY-RUN] Would remove plugin directory: {plugin_dir}")
                result.add("INFO", "would-remove-plugin", plugin, plugin_dir)
            else:
                out = wp.ssh(f"rm -rf '{plugin_dir}' && echo DONE || echo FAILED")
                if "DONE" in out:
                    ok(f"Removed rogue plugin: {plugin}")
                    result.add("INFO", "removed-plugin", plugin, plugin_dir)
                    deleted += 1
                else:
                    err(f"Could not remove plugin directory: {plugin}")
                    result.add("HIGH", "delete-failed", plugin, plugin_dir)
        else:
            info(f"Plugin not present: {plugin}")

    # ── E. Clear /tmp staging area ─────────────────────────────────────
    section("E. Clear /tmp staging")
    tmp_php = wp.ssh("find /tmp -name '*.php' 2>/dev/null | head -20")
    for path in [p.strip() for p in tmp_php.splitlines() if p.strip()]:
        if wp.dry_run:
            warn(f"[DRY-RUN] Would delete /tmp PHP: {path}")
        else:
            wp.ssh(f"rm -f '{path}'")
            ok(f"Cleared /tmp PHP: {path}")
            deleted += 1

    result.stat("files_deleted", deleted)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WP-Arsenal: Remove WordPress malware/shell files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_connection_args(parser)
    args = parser.parse_args()

    if not args.dry_run:
        print(f"\n{RED('WARNING')}: This script deletes files. "
              f"Run with {YELLOW('--dry-run')} first to preview.\n"
              "Continuing in 3 seconds... (Ctrl-C to abort)")
        import time; time.sleep(3)

    print_banner("WP-SHELL-NUKE — Remove Malware Files", args.dry_run)

    with WPConnection(args) as wp:
        result = nuke(wp, args)

    result.print_summary()

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()
