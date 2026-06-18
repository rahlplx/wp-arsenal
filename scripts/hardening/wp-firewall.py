#!/usr/bin/env python3
"""
wp-firewall.py — WordPress IP/geo-based access control via .htaccess
=====================================================================
Manages IP blocks and allowlists for any WordPress site on any host.
Works on Apache (most shared hosts). Not needed on Nginx hosts — use
server-level rules or Cloudflare instead.

Block IPs, protect wp-login.php, or geo-block countries (via Cloudflare
CF-IPCountry header or mod_geoip — auto-detected).

Usage:
  python wp-firewall.py --config config/config.yaml --block-ip "1.2.3.4"
  python wp-firewall.py --host H --user U --password P --wp-path W \\
      --block-ip "1.2.3.4,5.6.7.0/24"
  python wp-firewall.py ... --allow-admin-ip "YOUR_HOME_IP"
  python wp-firewall.py ... --block-country BD,RU,CN
  python wp-firewall.py ... --show
"""

import argparse
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wp_connect import (
    WPConnection, add_connection_args, print_banner, AuditResult,
    ok, warn, err, info, section, RED, YELLOW
)

try:
    from config_loader import load_config
    _HAS_CONFIG = True
except ImportError:
    _HAS_CONFIG = False


def _htaccess_marker(label: str) -> tuple:
    return f"# WP-Arsenal-FW-BEGIN:{label}", f"# WP-Arsenal-FW-END:{label}"


def _replace_block(content: str, label: str, new_block: str) -> str:
    begin, end = _htaccess_marker(label)
    if begin in content and end in content:
        start_idx = content.index(begin)
        end_idx   = content.index(end) + len(end)
        return content[:start_idx] + new_block + content[end_idx:]
    return content + "\n" + new_block


def build_ip_block(ips: list, trusted: list) -> str:
    """Build .htaccess block that denies listed IPs while preserving trusted ones."""
    # Filter out any accidental self-blocks
    to_block = [ip for ip in ips if not any(ip.startswith(t) for t in trusted)]
    if not to_block:
        return ""
    lines = [
        "# WP-Arsenal-FW-BEGIN:IP-BLOCK",
        "<RequireAll>",
        "  Require all granted",
    ]
    for ip in to_block:
        lines.append(f"  Require not ip {ip}")
    lines += ["</RequireAll>", "# WP-Arsenal-FW-END:IP-BLOCK"]
    return "\n".join(lines) + "\n"


def build_login_whitelist(ips: list) -> str:
    lines = [
        "# WP-Arsenal-FW-BEGIN:LOGIN-WHITELIST",
        "<Files wp-login.php>",
        "  <RequireAny>",
    ]
    for ip in ips:
        lines.append(f"    Require ip {ip}")
    lines += ["  </RequireAny>", "</Files>", "# WP-Arsenal-FW-END:LOGIN-WHITELIST"]
    return "\n".join(lines) + "\n"


def build_geo_block(countries: list) -> str:
    lines = ["# WP-Arsenal-FW-BEGIN:GEO-BLOCK"]
    for c in countries:
        lines.append(f"SetEnvIf CF-IPCountry {c.upper()} WPA_BlockGeo")
        lines.append(f"SetEnvIf X-Country-Code {c.upper()} WPA_BlockGeo")
    lines += [
        "SetEnvIfExpr \"reqenv('GEOIP_COUNTRY_CODE') =~ /" + "|".join(countries) + "/\" WPA_BlockGeo",
        "<RequireAll>",
        "  Require all granted",
        "  Require not env WPA_BlockGeo",
        "</RequireAll>",
        "# WP-Arsenal-FW-END:GEO-BLOCK",
    ]
    return "\n".join(lines) + "\n"


def is_apache(wp: WPConnection) -> bool:
    """Detect if site is running Apache (vs Nginx/LiteSpeed)."""
    server = wp.ssh("php -r 'echo php_uname(\"s\");' 2>/dev/null")
    htaccess_works = wp.wp_exists(".htaccess")
    return htaccess_works  # Good enough heuristic


def run_firewall(wp: WPConnection, args: argparse.Namespace) -> AuditResult:
    result = AuditResult("wp-firewall")

    if not is_apache(wp):
        warn("No .htaccess found — this site may use Nginx. "
             "Use server-level firewall or Cloudflare WAF instead.")
        result.add("MEDIUM", "no-htaccess", "No .htaccess — Nginx/LiteSpeed host", wp.wp_path)

    htaccess_path = wp.wp(".htaccess")
    htaccess = wp.sftp_read(htaccess_path).decode("utf-8", "replace")
    trusted  = getattr(args, "trusted_cidrs", []) or []
    changed  = False

    # ── Block IPs ─────────────────────────────────────────────────────
    if args.block_ip:
        ips = [ip.strip() for ip in args.block_ip.split(",") if ip.strip()]
        # Safety: refuse to block trusted CIDRs
        safe, skipped = [], []
        for ip in ips:
            if any(ip.startswith(t) for t in trusted):
                skipped.append(ip)
                warn(f"Skipped trusted IP: {ip}")
            else:
                safe.append(ip)

        if skipped:
            warn(f"Tip: remove {', '.join(skipped)} from --trusted-cidrs if you intend to block them")

        if safe:
            section(f"Blocking {len(safe)} IP(s): {', '.join(safe)}")
            new_block = build_ip_block(safe, trusted)
            if wp.dry_run:
                info(f"[DRY-RUN] Would add to .htaccess:\n{new_block}")
            else:
                htaccess = _replace_block(htaccess, "IP-BLOCK", new_block)
                changed = True
                for ip in safe:
                    ok(f"Queued block: {ip}")
                    result.add("INFO", "ip-blocked", ip, htaccess_path)

    # ── Login allowlist ────────────────────────────────────────────────
    if args.allow_admin_ip:
        allow_ips = [ip.strip() for ip in args.allow_admin_ip.split(",") if ip.strip()]
        section(f"wp-login.php whitelist: {', '.join(allow_ips)}")
        new_block = build_login_whitelist(allow_ips)
        if wp.dry_run:
            info(f"[DRY-RUN] Would add login whitelist:\n{new_block}")
        else:
            htaccess = _replace_block(htaccess, "LOGIN-WHITELIST", new_block)
            changed = True
            ok(f"Login whitelist set to: {', '.join(allow_ips)}")
            result.add("INFO", "login-whitelist", ", ".join(allow_ips), htaccess_path)

    # ── Country block ──────────────────────────────────────────────────
    if args.block_country:
        countries = [c.strip().upper() for c in args.block_country.split(",") if c.strip()]
        section(f"Country block: {', '.join(countries)}")
        geo_block = build_geo_block(countries)
        if wp.dry_run:
            info(f"[DRY-RUN] Would add geo-block:\n{geo_block}")
        else:
            htaccess = _replace_block(htaccess, "GEO-BLOCK", geo_block)
            changed = True
            ok(f"Geo-block applied for: {', '.join(countries)}")
            result.add("INFO", "geo-blocked", ", ".join(countries), htaccess_path)
            info("Note: geo-block requires Cloudflare (CF-IPCountry header) or mod_geoip on Apache")

    # ── Remove all WP-Arsenal firewall rules ───────────────────────────
    if args.clear:
        section("Clearing all WP-Arsenal firewall rules")
        for label in ["IP-BLOCK", "LOGIN-WHITELIST", "GEO-BLOCK"]:
            begin, end = _htaccess_marker(label)
            if begin in htaccess:
                htaccess = _replace_block(htaccess, label, "")
                ok(f"Removed: {label}")
        changed = True

    # ── Write updated .htaccess ────────────────────────────────────────
    if changed:
        if wp.sftp_write(htaccess_path, htaccess.encode()):
            ok(".htaccess updated")
        else:
            err("Failed to write .htaccess")
            result.add("CRITICAL", "write-failed", ".htaccess write failed", htaccess_path)

    # ── Show current rules ─────────────────────────────────────────────
    section("Current WP-Arsenal firewall rules")
    current_ht = wp.sftp_read(htaccess_path).decode("utf-8", "replace")
    if "WP-Arsenal-FW-BEGIN" in current_ht:
        for block in current_ht.split("WP-Arsenal-FW-BEGIN:")[1:]:
            label = block.split("\n")[0].strip()
            info(f"Active rule block: {label}")
    else:
        info("No WP-Arsenal firewall rules in .htaccess")

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WP-Arsenal: WordPress IP/geo firewall via .htaccess",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_connection_args(parser)
    parser.add_argument("--block-ip",       dest="block_ip",       default="",
                        help="Comma-separated IPs/CIDRs to block")
    parser.add_argument("--allow-admin-ip", dest="allow_admin_ip", default="",
                        help="Comma-separated IPs allowed to reach wp-login.php")
    parser.add_argument("--block-country",  dest="block_country",  default="",
                        help="Comma-separated 2-letter country codes to block")
    parser.add_argument("--clear", action="store_true",
                        help="Remove all WP-Arsenal firewall rules from .htaccess")
    parser.add_argument("--show", action="store_true",
                        help="Show current rules (no changes)")
    args = parser.parse_args()

    if _HAS_CONFIG:
        args = load_config(args)

    if not any([args.block_ip, args.allow_admin_ip, args.block_country, args.clear, args.show]):
        parser.error("Specify at least one action: --block-ip, --allow-admin-ip, "
                     "--block-country, --clear, or --show")

    print_banner("WP-FIREWALL — IP/Geo Access Control", args.dry_run)

    with WPConnection(args) as wp:
        result = run_firewall(wp, args)

    result.print_summary()
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()
