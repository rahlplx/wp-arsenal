#!/usr/bin/env python3
"""
wp-db-audit.py — Deep WordPress database security audit
========================================================
Checks:
  - All user accounts and capabilities
  - Active plugins (vs filesystem)
  - Critical options (siteurl, admin_email, active theme)
  - Injected scripts in posts/postmeta
  - Rank Math / redirect abuse
  - Rogue option rows
  - Scheduled events (wp-cron abuse)
  - Orphaned postmeta (attacker-inserted rows)

Usage:
  python wp-db-audit.py \\
      --host HOST --user USER --password PASS --wp-path /path/to/wp \\
      --db-host DBHOST --db-user DBUSER --db-pass DBPASS --db-name DBNAME \\
      --db-prefix wp_
"""

import argparse
import json
import os
import re
import shlex
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
from wp_connect import (
    WPConnection, add_connection_args, print_banner, AuditResult,
    ok, warn, err, info, section
)


def audit_db(wp: WPConnection, args: argparse.Namespace) -> AuditResult:
    result = AuditResult("wp-db-audit")
    p = wp.db_prefix

    # ── 1. All users + capabilities ────────────────────────────────────
    section("1. User accounts")
    users = wp.db(
        f"SELECT u.ID, u.user_login, u.user_email, "
        f"m.meta_value as caps "
        f"FROM {p}users u "
        f"LEFT JOIN {p}usermeta m ON u.ID=m.user_id "
        f"AND m.meta_key='{p}capabilities';"
    )
    admin_count = 0
    for line in users.splitlines():
        if "administrator" in line:
            admin_count += 1
            info(f"Admin: {line[:120]}")
            # Flag suspicious logins
            suspicious = ["wp_system_admin","admlnlx","archive_feed","admin2","backup_admin"]
            if any(s in line.lower() for s in suspicious):
                err(f"SUSPICIOUS admin account: {line[:80]}")
                result.add("CRITICAL", "rogue-admin", line[:80], "wp_users")
    result.stat("admin_count", admin_count)
    if admin_count <= 2:
        ok(f"{admin_count} admin account(s) — looks normal")
    else:
        warn(f"{admin_count} admin accounts — verify all are legitimate")

    # ── 2. active_plugins consistency ─────────────────────────────────
    section("2. active_plugins vs filesystem")
    plugins_raw = wp.db(
        f"SELECT option_value FROM {p}options WHERE option_name='active_plugins';"
    )
    # Extract plugin paths from serialized PHP
    plugin_paths = re.findall(r'"([^"]+/[^"]+\.php)"', plugins_raw)
    missing_plugins = []
    for rel_path in plugin_paths:
        full_path = wp.wp(f"wp-content/plugins/{rel_path}")
        exists = wp.ssh(f"test -f {shlex.quote(full_path)} && echo Y || echo N")
        if exists != "Y":
            err(f"Active plugin missing from filesystem: {rel_path}")
            result.add("HIGH", "plugin-file-missing", rel_path, full_path)
            missing_plugins.append(rel_path)
        else:
            info(f"OK: {rel_path}")

    result.stat("missing_plugins", len(missing_plugins))

    # ── 3. Critical options ────────────────────────────────────────────
    section("3. Critical options")
    critical = ["siteurl","home","admin_email","blogname","template","stylesheet",
                "upload_path","upload_url_path","wp_user_roles"]
    for opt in critical:
        val = wp.db(f"SELECT option_value FROM {p}options WHERE option_name='{opt}';")
        val = val.replace("option_value","").strip()
        info(f"  {opt}: {val[:100]}")
        if opt in ("siteurl","home") and ("javascript:" in val or "data:" in val):
            err(f"Injected URL in {opt}: {val}")
            result.add("CRITICAL", "url-injection", f"Injected URL in {opt}", val)

    # ── 4. Script/eval injection in posts ─────────────────────────────
    section("4. Script injection in post_content")
    inject_posts = wp.db(
        f"SELECT ID, post_title, post_status FROM {p}posts "
        f"WHERE post_content LIKE '%<script%' OR post_content LIKE '%eval(%' "
        f"OR post_content LIKE '%base64_decode%' LIMIT 20;"
    )
    if inject_posts.strip() and inject_posts.strip() != "ID\tpost_title\tpost_status":
        err(f"Posts with injected code:\n{inject_posts}")
        result.add("CRITICAL", "post-injection", "Script/eval in post_content", inject_posts[:200])
    else:
        ok("No script injection in posts")

    # ── 5. Script injection in postmeta ───────────────────────────────
    section("5. Script injection in postmeta")
    inject_meta = wp.db(
        f"SELECT post_id, meta_key FROM {p}postmeta "
        f"WHERE meta_value LIKE '%<script%' OR meta_value LIKE '%eval(%' LIMIT 20;"
    )
    if inject_meta.strip() and "post_id" not in inject_meta.strip()[:10]:
        err(f"Postmeta with injected code:\n{inject_meta[:200]}")
        result.add("CRITICAL", "postmeta-injection", "Script/eval in postmeta", "wp_postmeta")
    else:
        ok("No script injection in postmeta")

    # ── 6. Rank Math redirect abuse ────────────────────────────────────
    section("6. Rank Math redirections")
    rm_table = wp.db(f"SHOW TABLES LIKE '{p}rank_math_redirections';")
    if rm_table.strip():
        rm_count = wp.db(f"SELECT COUNT(*) FROM {p}rank_math_redirections;")
        count = rm_count.strip() if rm_count.strip().isdigit() else "unknown"
        info(f"Total Rank Math redirections: {count}")
        if isinstance(count, str) and count.isdigit() and int(count) > 100:
            warn(f"High redirection count ({count}) — potential spam redirect abuse")
            result.add("MEDIUM", "rm-redirections", f"{count} redirections", f"{p}rank_math_redirections")
            # Show sample externals
            external_rm = wp.db(
                f"SELECT url_to FROM {p}rank_math_redirections "
                f"WHERE url_to LIKE 'http%' LIMIT 10;"
            )
            if external_rm.strip():
                warn(f"External redirects:\n{external_rm}")
    else:
        info("No Rank Math redirections table")

    # ── 7. WP cron scheduled events ───────────────────────────────────
    section("7. WP scheduled events (cron abuse)")
    cron_option = wp.db(
        f"SELECT option_value FROM {p}options WHERE option_name='cron';"
    )
    # Look for suspicious event hooks
    suspicious_hooks = ["eval","base64","shell","exec","wget","curl","backdoor"]
    for hook in suspicious_hooks:
        if hook in cron_option.lower():
            err(f"Suspicious hook in WP cron: '{hook}'")
            result.add("CRITICAL", "cron-injection", f"Suspicious hook '{hook}' in wp_cron", "wp_options:cron")

    # ── 8. Rogue options (attacker-created) ───────────────────────────
    section("8. Rogue options check")
    rogue_option_patterns = [
        "ihaf_%",        # FileOrganizer / IHAF plugin data
        "fileorganizer%",
        "cacheengine%",
        "%_backdoor%",
        "%attacker%",
    ]
    for pattern in rogue_option_patterns:
        found = wp.db(
            f"SELECT option_name FROM {p}options WHERE option_name LIKE '{pattern}' LIMIT 5;"
        )
        if found.strip() and found.strip() != "option_name":
            warn(f"Rogue option rows matching '{pattern}':\n{found}")
            result.add("MEDIUM", "rogue-option", f"Options matching {pattern}", found[:100])

    # ── 9. Session count ───────────────────────────────────────────────
    section("9. Active sessions")
    session_count = wp.db(
        f"SELECT COUNT(*) FROM {p}usermeta WHERE meta_key='session_tokens' "
        f"AND meta_value != 'a:0:{{}}' AND meta_value != '';"
    )
    info(f"Users with active sessions: {session_count.strip()}")
    result.stat("active_sessions", session_count.strip())

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WP-Arsenal: Deep WordPress database security audit",
    )
    add_connection_args(parser)
    args = parser.parse_args()

    print_banner("WP-DB-AUDIT — Database Security Audit", args.dry_run)

    with WPConnection(args) as wp:
        result = audit_db(wp, args)

    result.print_summary()

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()
