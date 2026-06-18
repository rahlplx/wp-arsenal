#!/usr/bin/env python3
"""
wp-user-audit.py — WordPress user and role security audit
==========================================================
Detects rogue admin accounts, recently-created suspicious users,
weak roles, and attacker-linked accounts. Can also delete or
demote specified users.

Checks:
  A. All users with admin-level capabilities
  B. Users created after a specified date (--since YYYY-MM-DD)
  C. Known-bad username patterns (attacker toolkit signatures)
  D. Users with no email or temp/disposable email domains
  E. Session tokens — who is currently logged in and from where
  F. Last-login metadata from usermeta

Usage:
  python wp-user-audit.py --config config/config.yaml
  python wp-user-audit.py --config config/config.yaml --since 2025-01-01
  python wp-user-audit.py --config config/config.yaml --delete-user rogue_admin --dry-run
  python wp-user-audit.py --config config/config.yaml --demote-user rogue_user --role subscriber
  python wp-user-audit.py --config config/config.yaml --kill-sessions all
"""

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
from wp_connect import (
    WPConnection, add_connection_args, print_banner, AuditResult,
    ok, warn, err, info, section
)

# Username patterns associated with attacker toolkits
BAD_USERNAME_PATTERNS = [
    r"^archive_feed$",
    r"^wp_system_admin$",
    r"^adm[il]n[il]x$",
    r"^wordpress_admin\d+$",
    r"^admin\d{4,}$",
    r"^test_?admin",
    r"^backup_?user",
    r"^support_?\d+$",
    r"^user_\d{6,}$",
]

# Disposable/throwaway email domains (common in rogue accounts)
TEMP_EMAIL_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "tempmail.com", "throwam.com",
    "yopmail.com", "sharklasers.com", "guerrillamailblock.com", "grr.la",
    "spam4.me", "trashmail.com", "discard.email", "fakeinbox.com",
}


def get_all_users(wp: WPConnection) -> list[dict]:
    """Return list of all WP users with basic fields."""
    p = wp.db_prefix
    rows = wp.db(
        f"SELECT u.ID, u.user_login, u.user_email, u.user_registered, "
        f"       um.meta_value as capabilities "
        f"FROM {p}users u "
        f"LEFT JOIN {p}usermeta um "
        f"  ON u.ID = um.user_id AND um.meta_key = '{p}capabilities' "
        f"ORDER BY u.ID;"
    )
    users = []
    for line in rows.strip().splitlines():
        parts = line.strip().split("\t")
        if len(parts) < 4 or parts[0] == "ID":
            continue
        uid, login, email, registered = parts[0], parts[1], parts[2], parts[3]
        caps_raw = parts[4] if len(parts) > 4 else ""
        users.append({
            "id": uid,
            "login": login,
            "email": email,
            "registered": registered,
            "caps_raw": caps_raw,
        })
    return users


def has_admin_cap(caps_raw: str) -> bool:
    """Return True if capabilities include administrator."""
    return '"administrator"' in caps_raw or "'administrator'" in caps_raw


def has_editor_cap(caps_raw: str) -> bool:
    return '"editor"' in caps_raw


def get_session_ips(wp: WPConnection) -> dict[str, list[str]]:
    """Extract {user_id: [ip, ...]} from session_tokens usermeta."""
    p = wp.db_prefix
    rows = wp.db(
        f"SELECT user_id, meta_value FROM {p}usermeta "
        f"WHERE meta_key = 'session_tokens';"
    )
    result: dict[str, list[str]] = {}
    ip_pattern = re.compile(r'"ip";s:\d+:"([^"]+)"')
    for line in rows.strip().splitlines():
        parts = line.strip().split("\t", 1)
        if len(parts) < 2 or parts[0] == "user_id":
            continue
        uid, tokens_raw = parts[0], parts[1]
        ips = ip_pattern.findall(tokens_raw)
        if ips:
            result[uid] = ips
    return result


def delete_user(wp: WPConnection, login: str, result: AuditResult) -> None:
    """Delete a WordPress user by login (posts reassigned to user ID 1)."""
    p = wp.db_prefix
    safe_login = WPConnection.sql_escape(login)
    uid_row = wp.db(
        f"SELECT ID FROM {p}users WHERE user_login = '{safe_login}' LIMIT 1;"
    )
    uid = uid_row.strip().splitlines()[-1].strip() if uid_row.strip() else ""
    if not uid or not uid.isdigit():
        err(f"User '{login}' not found")
        return

    if wp.dry_run:
        info(f"[DRY-RUN] Would delete user ID {uid} ({login})")
        return

    # Delete usermeta first, then user
    wp.db_write(f"DELETE FROM {p}usermeta WHERE user_id = '{uid}';")
    wp.db_write(f"DELETE FROM {p}users WHERE ID = '{uid}';")
    # Reassign posts to admin (ID=1)
    wp.db_write(
        f"UPDATE {p}posts SET post_author = '1' "
        f"WHERE post_author = '{uid}';"
    )
    ok(f"Deleted user: {login} (ID {uid})")
    result.add("INFO", "user-deleted", f"Deleted user {login} (ID {uid})", "")


def demote_user(wp: WPConnection, login: str, new_role: str, result: AuditResult) -> None:
    """Change a user's WordPress role."""
    p = wp.db_prefix
    safe_login = WPConnection.sql_escape(login)
    uid_row = wp.db(
        f"SELECT ID FROM {p}users WHERE user_login = '{safe_login}' LIMIT 1;"
    )
    uid = uid_row.strip().splitlines()[-1].strip() if uid_row.strip() else ""
    if not uid or not uid.isdigit():
        err(f"User '{login}' not found")
        return

    role_map = {
        "administrator": 'a:1:{s:13:"administrator";b:1;}',
        "editor":        'a:1:{s:6:"editor";b:1;}',
        "author":        'a:1:{s:6:"author";b:1;}',
        "contributor":   'a:1:{s:11:"contributor";b:1;}',
        "subscriber":    'a:1:{s:10:"subscriber";b:1;}',
    }
    if new_role not in role_map:
        err(f"Unknown role '{new_role}'. Valid: {', '.join(role_map)}")
        return

    if wp.dry_run:
        info(f"[DRY-RUN] Would set {login} → {new_role}")
        return

    serialized = role_map[new_role]
    wp.db_write(
        f"UPDATE {p}usermeta SET meta_value = '{serialized}' "
        f"WHERE user_id = '{uid}' AND meta_key = '{p}capabilities';"
    )
    ok(f"Set {login} → {new_role}")
    result.add("INFO", "user-demoted", f"{login} set to {new_role}", "")


def kill_sessions(wp: WPConnection, target: str, result: AuditResult) -> None:
    """Kill all sessions or sessions for a specific user."""
    p = wp.db_prefix
    if target == "all":
        if wp.dry_run:
            count = wp.db(
                f"SELECT COUNT(*) FROM {p}usermeta WHERE meta_key = 'session_tokens';"
            )
            info(f"[DRY-RUN] Would clear sessions for {count.strip()} users")
        else:
            wp.db_write(
                f"UPDATE {p}usermeta SET meta_value = 'a:0:{{}}' "
                f"WHERE meta_key = 'session_tokens';"
            )
            ok("All WordPress sessions terminated")
            result.add("INFO", "sessions-killed", "All sessions terminated", "")
    else:
        safe_target = WPConnection.sql_escape(target)
        uid_row = wp.db(
            f"SELECT ID FROM {p}users WHERE user_login = '{safe_target}' LIMIT 1;"
        )
        uid = uid_row.strip().splitlines()[-1].strip() if uid_row.strip() else ""
        if not uid or not uid.isdigit():
            err(f"User '{target}' not found")
            return
        if wp.dry_run:
            info(f"[DRY-RUN] Would kill sessions for user {target}")
        else:
            wp.db_write(
                f"UPDATE {p}usermeta SET meta_value = 'a:0:{{}}' "
                f"WHERE user_id = '{uid}' AND meta_key = 'session_tokens';"
            )
            ok(f"Sessions killed for user: {target}")
            result.add("INFO", "sessions-killed", f"Sessions killed for {target}", "")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WP-Arsenal: WordPress user and role security audit"
    )
    add_connection_args(parser)
    parser.add_argument("--since", default="",
                        help="Flag users registered after this date (YYYY-MM-DD)")
    parser.add_argument("--delete-user", dest="delete_user", default="",
                        help="Delete this user by login (use --dry-run first)")
    parser.add_argument("--demote-user", dest="demote_user", default="",
                        help="User login to demote")
    parser.add_argument("--role", default="subscriber",
                        help="New role for --demote-user (default: subscriber)")
    parser.add_argument("--kill-sessions", dest="kill_sessions", default="",
                        help="Kill sessions: 'all' or specific username")
    args = parser.parse_args()

    print_banner("WP-USER-AUDIT — User & Role Security Audit", args.dry_run)
    result = AuditResult("wp-user-audit")

    with WPConnection(args) as wp:

        # ── Execute actions first ─────────────────────────────────────
        if args.delete_user:
            section(f"Delete user: {args.delete_user}")
            delete_user(wp, args.delete_user, result)
            result.print_summary()
            return

        if args.demote_user:
            section(f"Demote user: {args.demote_user} → {args.role}")
            demote_user(wp, args.demote_user, args.role, result)
            result.print_summary()
            return

        if args.kill_sessions:
            section(f"Kill sessions: {args.kill_sessions}")
            kill_sessions(wp, args.kill_sessions, result)
            result.print_summary()
            return

        # ── Audit mode ───────────────────────────────────────────────
        section("A. All users")
        users = get_all_users(wp)
        info(f"Total users: {len(users)}")
        result.stat("total_users", len(users))

        admins = [u for u in users if has_admin_cap(u["caps_raw"])]
        editors = [u for u in users if has_editor_cap(u["caps_raw"]) and not has_admin_cap(u["caps_raw"])]

        section("B. Administrator accounts")
        for u in admins:
            info(f"  [ADMIN] ID={u['id']:4}  {u['login']:30}  {u['email']:40}  registered: {u['registered']}")
        result.stat("admin_count", len(admins))
        if len(admins) > 2:
            warn(f"{len(admins)} admin accounts found — review carefully")
            result.add("MEDIUM", "many-admins", f"{len(admins)} admin accounts", "")

        section("C. Editor accounts")
        for u in editors:
            info(f"  [EDITOR] ID={u['id']:4}  {u['login']:30}  {u['email']}")

        section("D. Suspicious usernames")
        for u in users:
            for pat in BAD_USERNAME_PATTERNS:
                if re.match(pat, u["login"], re.IGNORECASE):
                    err(f"  SUSPICIOUS: {u['login']} (ID {u['id']}) — matches pattern {pat}")
                    result.add("HIGH", "bad-username", f"Suspicious username: {u['login']}", "")
                    break

        section("E. Disposable/temp email domains")
        for u in users:
            if "@" in u["email"]:
                domain = u["email"].split("@", 1)[1].lower()
                if domain in TEMP_EMAIL_DOMAINS:
                    err(f"  TEMP EMAIL: {u['login']} uses {u['email']}")
                    result.add("HIGH", "temp-email", f"{u['login']} has temp email: {u['email']}", "")

        if args.since:
            section(f"F. Users registered after {args.since}")
            for u in users:
                if u["registered"] >= args.since:
                    sev = "HIGH" if has_admin_cap(u["caps_raw"]) else "MEDIUM"
                    flag = "[ADMIN] " if has_admin_cap(u["caps_raw"]) else ""
                    warn(f"  {flag}{u['login']} (ID {u['id']}) registered {u['registered']}")
                    result.add(sev, "new-user",
                               f"{flag}User created after {args.since}: {u['login']} ({u['email']})", "")

        section("G. Active sessions (who is logged in now)")
        sessions = get_session_ips(wp)
        if sessions:
            for uid, ips in sessions.items():
                matching = [u for u in users if u["id"] == uid]
                login = matching[0]["login"] if matching else f"ID:{uid}"
                ip_str = ", ".join(set(ips))
                info(f"  Active session: {login} from IP(s): {ip_str}")
                result.add("INFO", "active-session", f"{login} logged in from {ip_str}", "")
        else:
            ok("No active sessions")

        section("H. REST API user enumeration (zero-auth)")
        if wp.site_url:
            api_body = wp.http_body(f"{wp.site_url.rstrip('/')}/wp-json/wp/v2/users")
            if not api_body:
                ok("REST API user enumeration not accessible")
            else:
                try:
                    parsed = json.loads(api_body)
                except json.JSONDecodeError:
                    parsed = None

                if isinstance(parsed, list) and parsed and all(isinstance(u, dict) for u in parsed):
                    err(f"REST API user enumeration enabled — {len(parsed)} user(s) exposed:")
                    for u in parsed:
                        info(f"  ID={u.get('id','')}  slug={u.get('slug','')}  name={u.get('name','')}")
                    result.add(
                        "HIGH", "rest-api-user-enum",
                        f"REST API exposes {len(parsed)} user(s) without authentication",
                        f"{wp.site_url}/wp-json/wp/v2/users"
                    )
                else:
                    ok("REST API user endpoint requires authentication (blocked)")
        else:
            info("--site-url not provided — skipping REST API enumeration check")

    result.print_summary()
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()
