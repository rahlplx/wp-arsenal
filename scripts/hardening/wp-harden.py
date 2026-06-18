#!/usr/bin/env python3
"""
wp-harden.py — WordPress security hardening
============================================
Applies a comprehensive hardening checklist to a WordPress site:
  - wp-config.php security constants
  - .htaccess protections (WP includes, xmlrpc, file browsing)
  - Uploads PHP execution block
  - File editor disable
  - Pingback/xmlrpc lockdown
  - wp-cron server-only restriction

Run with --dry-run first to preview every change.

Usage:
  python wp-harden.py \\
      --host HOST --user USER --password PASS --wp-path /path/to/wp \\
      --db-host DBHOST --db-user DBUSER --db-pass DBPASS --db-name DBNAME \\
      --db-prefix wp_ [--dry-run]
"""

import argparse
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wp_connect import (
    WPConnection, add_connection_args, print_banner, AuditResult,
    ok, warn, err, info, section
)

# ── Hardening snippets ─────────────────────────────────────────────────────

WPCONFIG_ADDITIONS = """
/* ── WP-Arsenal Hardening ── */
define( 'DISALLOW_FILE_EDIT', true );
define( 'DISALLOW_FILE_MODS', false );   // Set true to also block plugin installs
define( 'WP_DEBUG', false );
define( 'DISALLOW_UNFILTERED_HTML', true );
define( 'FORCE_SSL_ADMIN', true );
define( 'WP_POST_REVISIONS', 5 );
define( 'EMPTY_TRASH_DAYS', 7 );
define( 'WP_AUTO_UPDATE_CORE', 'minor' );
"""

HTACCESS_SECURITY_BLOCK = """
# ── WP-Arsenal: Security rules ──────────────────────────────────────────
# Block access to wp-includes
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^wp-admin/includes/ - [F,L]
RewriteRule !^wp-includes/ - [S=3]
RewriteRule ^wp-includes/[^/]+\\.php$ - [F,L]
RewriteRule ^wp-includes/js/tinymce/langs/.+\\.php - [F,L]
RewriteRule ^wp-includes/theme-compat/ - [F,L]
</IfModule>

# Block xmlrpc brute force
<Files xmlrpc.php>
    <RequireAll>
        Require all denied
    </RequireAll>
</Files>

# Block file browsing
Options -Indexes

# Protect wp-config
<Files wp-config.php>
    <RequireAll>
        Require all denied
    </RequireAll>
</Files>

# Block .htaccess and hidden files
<FilesMatch "^\\.">
    <RequireAll>
        Require all denied
    </RequireAll>
</FilesMatch>

# Block PHP execution in uploads (belt-and-suspenders)
<FilesMatch "\\.php$">
    <RequireAll>
        Require all denied
    </RequireAll>
</FilesMatch>
# ── End WP-Arsenal ──────────────────────────────────────────────────────
"""

UPLOADS_HTACCESS = """# WP-Arsenal: Block PHP in uploads
<Files *.php>
deny from all
</Files>
"""


def apply_hardening(wp: WPConnection, args: argparse.Namespace) -> AuditResult:
    result = AuditResult("wp-harden")
    p = wp.db_prefix

    # ── 1. wp-config.php hardening constants ──────────────────────────
    section("1. wp-config.php — security constants")
    wpconfig_content = wp.sftp_read(wp.wp("wp-config.php")).decode("utf-8", "replace")

    missing_constants = []
    for const in ["DISALLOW_FILE_EDIT", "WP_DEBUG", "FORCE_SSL_ADMIN"]:
        if const not in wpconfig_content:
            missing_constants.append(const)

    if missing_constants:
        warn(f"Missing constants: {', '.join(missing_constants)}")
        if not wp.dry_run:
            # Insert before the "That's all, stop editing!" line
            marker = "/* That's all, stop editing!"
            if marker in wpconfig_content:
                new_content = wpconfig_content.replace(
                    marker,
                    WPCONFIG_ADDITIONS + "\n" + marker
                )
                wp.sftp_write(wp.wp("wp-config.php"), new_content.encode())
                ok("Added security constants to wp-config.php")
                result.add("INFO", "hardened", "Security constants added to wp-config.php", wp.wp("wp-config.php"))
            else:
                warn("Could not find insertion point in wp-config.php — add constants manually")
        else:
            info(f"[DRY-RUN] Would add: {', '.join(missing_constants)}")
    else:
        ok("wp-config.php security constants already present")

    # ── 2. Root .htaccess — security block ────────────────────────────
    section("2. Root .htaccess — security rules")
    htaccess_content = wp.sftp_read(wp.wp(".htaccess")).decode("utf-8", "replace")

    if "WP-Arsenal: Security rules" in htaccess_content:
        ok(".htaccess security block already present")
    else:
        if wp.dry_run:
            info("[DRY-RUN] Would append security block to .htaccess")
        else:
            new_ht = htaccess_content + "\n" + HTACCESS_SECURITY_BLOCK
            wp.sftp_write(wp.wp(".htaccess"), new_ht.encode())
            ok("Appended security rules to .htaccess")
            result.add("INFO", "hardened", "Security block added to .htaccess", wp.wp(".htaccess"))

    # ── 3. uploads/ .htaccess ─────────────────────────────────────────
    section("3. Block PHP in uploads/")
    uploads_ht = wp.wp("wp-content/uploads/.htaccess")
    existing_upl_ht = wp.sftp_read(uploads_ht)
    if b"deny from all" in existing_upl_ht:
        ok("uploads/.htaccess already blocks PHP")
    else:
        if not wp.dry_run:
            wp.sftp_write(uploads_ht, UPLOADS_HTACCESS.encode())
            ok("PHP execution blocked in uploads/")
            result.add("INFO", "hardened", "PHP blocked in uploads/", uploads_ht)
        else:
            info("[DRY-RUN] Would write PHP-blocking .htaccess to uploads/")

    # ── 4. Lock wp-cron.php to server-only ────────────────────────────
    section("4. Lock wp-cron.php to server-only access")
    htaccess_content2 = wp.sftp_read(wp.wp(".htaccess")).decode("utf-8", "replace")
    if "wp-cron" not in htaccess_content2:
        cron_block = """
# WP-Arsenal: Block external wp-cron access
<Files wp-cron.php>
    <RequireAll>
        Require all denied
    </RequireAll>
</Files>
"""
        if not wp.dry_run:
            updated = wp.sftp_read(wp.wp(".htaccess"))
            wp.sftp_write(wp.wp(".htaccess"), updated + cron_block.encode())
            ok("wp-cron.php locked to server-only")
            result.add("INFO", "hardened", "wp-cron.php locked", wp.wp(".htaccess"))
        else:
            info("[DRY-RUN] Would lock wp-cron.php")
    else:
        ok("wp-cron.php already locked")

    # ── 5. DB — disable xmlrpc pingbacks ──────────────────────────────
    section("5. Disable pingbacks")
    if not wp.dry_run:
        wp.db_write(
            f"UPDATE {p}options SET option_value='closed' "
            f"WHERE option_name IN ('default_ping_status','default_pingback_flag');"
        )
        ok("Pingbacks disabled in DB")
        result.add("INFO", "hardened", "Pingbacks disabled", "wp_options")
    else:
        info("[DRY-RUN] Would disable pingbacks in DB")

    # ── 6. Disable file editing via DB (belt-and-suspenders) ──────────
    section("6. Disable WP Theme/Plugin editor via DB")
    if not wp.dry_run:
        # Also add as option in case wp-config.php write failed
        existing = wp.db(
            f"SELECT option_value FROM {p}options WHERE option_name='disallow_file_edit';"
        )
        if not existing.strip():
            wp.db_write(
                f"INSERT INTO {p}options (option_name, option_value, autoload) "
                f"VALUES ('disallow_file_edit', '1', 'yes') "
                f"ON DUPLICATE KEY UPDATE option_value='1';"
            )
            ok("File editor disabled in DB")
    else:
        info("[DRY-RUN] Would disable file editor in DB")

    # ── 7. Report ──────────────────────────────────────────────────────
    result.stat("hardening_applied", "complete" if not wp.dry_run else "dry-run")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WP-Arsenal: WordPress security hardening",
    )
    add_connection_args(parser)
    args = parser.parse_args()

    print_banner("WP-HARDEN — WordPress Security Hardening", args.dry_run)

    with WPConnection(args) as wp:
        result = apply_hardening(wp, args)

    result.print_summary()

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()
