#!/usr/bin/env python3
"""
wp-network-audit.py — WordPress Multisite Network security audit
=================================================================
Audits a WordPress Network (Multisite) installation:
  - Detects whether this WP install is a network
  - Lists all sub-sites with their domain, path, status, and registration date
  - Identifies super-admins (network-level administrators)
  - Checks network-activated (sitewide) plugins vs filesystem
  - Checks per-site active plugins for each sub-site
  - Flags suspicious sub-sites (spam, inactive, recently created)
  - Checks user registration settings (open registration = risk)
  - Reports network-level options that affect security

Supports both sub-domain and sub-directory network installs.

Usage:
  python wp-network-audit.py --config config/config.yaml
  python wp-network-audit.py --config config/config.yaml --list-sites
  python wp-network-audit.py --config config/config.yaml --site-id 3
  python wp-network-audit.py --config config/config.yaml --json > network-audit.json
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


def is_network_install(wp: WPConnection) -> bool:
    """Check if MULTISITE constant is set in wp-config.php."""
    out = wp.ssh(
        f"grep -E \"define.*MULTISITE.*true\" {shlex.quote(wp.wp_path + '/wp-config.php')} 2>/dev/null"
    )
    return bool(out.strip())


def get_network_sites(wp: WPConnection) -> list[dict]:
    """List all blogs from wp_blogs table."""
    p = wp.db_prefix
    rows = wp.db(
        f"SELECT blog_id, site_id, domain, path, registered, last_updated, "
        f"public, archived, mature, spam, deleted "
        f"FROM {p}blogs ORDER BY blog_id;"
    )
    sites = []
    for line in rows.strip().splitlines():
        parts = line.strip().split("\t")
        if len(parts) < 11 or parts[0] == "blog_id":
            continue
        sites.append({
            "blog_id":      parts[0],
            "site_id":      parts[1],
            "domain":       parts[2],
            "path":         parts[3],
            "registered":   parts[4],
            "last_updated": parts[5],
            "public":       parts[6],
            "archived":     parts[7],
            "mature":       parts[8],
            "spam":         parts[9],
            "deleted":      parts[10],
        })
    return sites


def get_super_admins(wp: WPConnection) -> list[str]:
    """Read site_admins from wp_sitemeta — these are super-admins."""
    p = wp.db_prefix
    raw = wp.db(
        f"SELECT meta_value FROM {p}sitemeta "
        f"WHERE meta_key='site_admins' LIMIT 1;"
    )
    if not raw.strip():
        return []
    # Serialized PHP: a:N:{i:0;s:LEN:"login";...}
    logins = re.findall(r's:\d+:"([^"]+)"', raw)
    return logins


def get_network_plugins(wp: WPConnection) -> list[str]:
    """Get network-activated (sitewide) plugins from wp_sitemeta."""
    p = wp.db_prefix
    raw = wp.db(
        f"SELECT meta_value FROM {p}sitemeta "
        f"WHERE meta_key='active_sitewide_plugins' LIMIT 1;"
    )
    if not raw.strip():
        return []
    # Serialized array keys are plugin paths: s:LEN:"slug/file.php"
    return re.findall(r'"([^"]+\.php)"', raw)


def get_site_plugins(wp: WPConnection, blog_id: str) -> list[str]:
    """Get active plugins for a specific sub-site."""
    p = wp.db_prefix
    prefix = f"{p}{blog_id}_" if blog_id != "1" else p
    raw = wp.db(
        f"SELECT option_value FROM {prefix}options "
        f"WHERE option_name='active_plugins' LIMIT 1;"
    )
    if not raw.strip():
        return []
    return re.findall(r'"([^"]+\.php)"', raw)


def get_site_option(wp: WPConnection, blog_id: str, option: str) -> str:
    """Get a specific option from a sub-site's options table."""
    p = wp.db_prefix
    prefix = f"{p}{blog_id}_" if blog_id != "1" else p
    row = wp.db(
        f"SELECT option_value FROM {prefix}options "
        f"WHERE option_name='{option}' LIMIT 1;"
    )
    return row.strip().splitlines()[-1].strip() if row.strip() else ""


def get_registration_setting(wp: WPConnection) -> str:
    """Check who can register on this network (none/user/blog/all)."""
    p = wp.db_prefix
    row = wp.db(
        f"SELECT meta_value FROM {p}sitemeta "
        f"WHERE meta_key='registration' LIMIT 1;"
    )
    return row.strip().splitlines()[-1].strip() if row.strip() else "unknown"


def plugin_on_filesystem(wp: WPConnection, plugin_path: str) -> bool:
    """Check if a plugin file exists on the filesystem."""
    slug = plugin_path.split("/")[0] if "/" in plugin_path else plugin_path
    return wp.wp_exists(f"wp-content/plugins/{slug}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WP-Arsenal: WordPress Multisite Network security audit"
    )
    add_connection_args(parser)
    parser.add_argument("--list-sites", action="store_true",
                        help="List all sub-sites and exit")
    parser.add_argument("--site-id", dest="site_id", default="",
                        help="Audit a specific sub-site by blog_id")
    args = parser.parse_args()

    print_banner("WP-NETWORK-AUDIT — WordPress Multisite Security Audit", args.dry_run)
    result = AuditResult("wp-network-audit")

    with WPConnection(args) as wp:

        # ── Detect multisite ─────────────────────────────────────────────
        section("1. Network detection")
        is_network = is_network_install(wp)
        if not is_network:
            warn("MULTISITE constant not found in wp-config.php")
            warn("This does not appear to be a WordPress Network install.")
            info("If this is a new network setup, ensure MULTISITE and related constants are set.")
            result.add("INFO", "not-network", "Not a WordPress Multisite install", wp.wp_path)
            result.print_summary()
            return
        ok("WordPress Multisite detected")

        # ── Registration settings ────────────────────────────────────────
        section("2. Registration settings")
        registration = get_registration_setting(wp)
        reg_labels = {
            "none": "Disabled (safest)",
            "user": "User registration open",
            "blog": "Site registration open",
            "all":  "User and site registration open (highest risk)",
        }
        label = reg_labels.get(registration, registration)
        if registration in ("blog", "all"):
            err(f"Registration setting: {registration} — {label}")
            result.add("HIGH", "open-registration",
                       f"Network allows public site registration ('{registration}')", "")
        elif registration == "user":
            warn(f"Registration setting: {registration} — {label}")
            result.add("MEDIUM", "user-registration",
                       "Network allows public user registration", "")
        else:
            ok(f"Registration setting: {registration} — {label}")

        # ── Super admins ─────────────────────────────────────────────────
        section("3. Super-admin accounts")
        super_admins = get_super_admins(wp)
        info(f"Super-admins ({len(super_admins)}): {', '.join(super_admins)}")
        result.stat("super_admins", len(super_admins))
        if len(super_admins) > 2:
            warn(f"{len(super_admins)} super-admins — review for rogue accounts")
            result.add("MEDIUM", "many-super-admins",
                       f"{len(super_admins)} super-admin accounts", "")

        # ── Network-activated plugins ────────────────────────────────────
        section("4. Network-activated (sitewide) plugins")
        network_plugins = get_network_plugins(wp)
        info(f"Network-activated plugins: {len(network_plugins)}")
        for plugin in network_plugins:
            slug = plugin.split("/")[0]
            if plugin_on_filesystem(wp, plugin):
                ok(f"  {plugin}")
            else:
                err(f"  MISSING: {plugin} (active network-wide but not on filesystem)")
                result.add("CRITICAL", "network-plugin-missing",
                           f"Network plugin missing from filesystem: {plugin}", "")

        # ── All sub-sites ────────────────────────────────────────────────
        section("5. Sub-site inventory")
        sites = get_network_sites(wp)
        info(f"Total sub-sites: {len(sites)}")
        result.stat("total_sites", len(sites))

        if args.list_sites:
            for s in sites:
                flags = ""
                if s["spam"] == "1":    flags += " [SPAM]"
                if s["deleted"] == "1": flags += " [DELETED]"
                if s["archived"] == "1": flags += " [ARCHIVED]"
                print(f"  ID={s['blog_id']:4}  {s['domain']}{s['path']:20}  "
                      f"registered={s['registered'][:10]}{flags}")
            result.print_summary()
            return

        # Filter to specific site if requested
        audit_sites = sites
        if args.site_id:
            audit_sites = [s for s in sites if s["blog_id"] == args.site_id]
            if not audit_sites:
                err(f"No sub-site found with blog_id={args.site_id}")
                return

        # ── Per-site checks ──────────────────────────────────────────────
        section("6. Per-site security checks")
        for site in audit_sites:
            bid = site["blog_id"]
            domain = site["domain"] + site["path"]
            flags = []

            if site["spam"] == "1":
                err(f"  [SPAM]    ID={bid}  {domain}")
                result.add("HIGH", "spam-site", f"Sub-site marked as spam: {domain}", "")
                flags.append("spam")

            if site["deleted"] == "1":
                warn(f"  [DELETED] ID={bid}  {domain}")
                flags.append("deleted")

            if site["archived"] == "1":
                warn(f"  [ARCHIVED] ID={bid}  {domain}")
                flags.append("archived")

            # Check per-site plugins vs filesystem
            site_plugins = get_site_plugins(wp, bid)
            missing = [p for p in site_plugins if not plugin_on_filesystem(wp, p)]
            if missing:
                for p in missing:
                    err(f"  ID={bid} ({domain}): plugin missing: {p}")
                    result.add("HIGH", "site-plugin-missing",
                               f"Site {bid} ({domain}): plugin missing: {p}", "")

            # Check siteurl matches expected domain
            siteurl = get_site_option(wp, bid, "siteurl")
            expected_domain = site["domain"].rstrip("/")
            if siteurl and expected_domain and expected_domain not in siteurl:
                warn(f"  ID={bid}: siteurl mismatch — DB domain={expected_domain}, "
                     f"options.siteurl={siteurl}")
                result.add("MEDIUM", "siteurl-mismatch",
                           f"Site {bid}: siteurl mismatch ({siteurl} vs {expected_domain})", "")

            if not flags and not missing:
                ok(f"  ID={bid}  {domain}  (registered {site['registered'][:10]})")

        # ── Network options security review ──────────────────────────────
        section("7. Network security options")
        p = wp.db_prefix

        # Check if admin email is set
        admin_email = wp.db(
            f"SELECT meta_value FROM {p}sitemeta WHERE meta_key='admin_email' LIMIT 1;"
        )
        if admin_email.strip():
            info(f"Network admin email: {admin_email.strip().splitlines()[-1]}")

        # Check upload filetypes
        upload_filetypes = wp.db(
            f"SELECT meta_value FROM {p}sitemeta WHERE meta_key='upload_filetypes' LIMIT 1;"
        )
        if upload_filetypes.strip():
            ft = upload_filetypes.strip().splitlines()[-1]
            risky = [x for x in ["php", "php5", "phtml", "exe", "sh"] if x in ft.lower()]
            if risky:
                err(f"Dangerous upload filetypes allowed: {', '.join(risky)}")
                result.add("CRITICAL", "dangerous-uploads",
                           f"Network allows upload of: {', '.join(risky)}", "")
            else:
                ok(f"Upload filetypes: {ft[:80]}")

        # Check illegal names (reserved blog paths)
        illegal_names = wp.db(
            f"SELECT meta_value FROM {p}sitemeta WHERE meta_key='illegal_names' LIMIT 1;"
        )
        if not illegal_names.strip():
            warn("No illegal_names set — attackers could register reserved paths like /wp-admin/")
            result.add("MEDIUM", "no-illegal-names",
                       "Network has no reserved/illegal sub-site names defined", "")

    result.print_summary()
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()
