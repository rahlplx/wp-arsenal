#!/usr/bin/env python3
"""
wp-attacker-profile.py — Build attacker IP/identity profile from WP data
=========================================================================
Extracts attacker fingerprints from:
  - WP session_tokens (user meta) — unmasked real IPs if attacker had no VPN
  - Honeypot trigger log entries from error_log / debug.log
  - Login monitor alert entries
  - Rogue admin accounts in wp_users

Cross-references IPs against a configurable ISP map (or queries whois).
Outputs a structured profile suitable for police/ISP abuse reports.

Usage:
  python wp-attacker-profile.py \\
      --host HOST --user USER --password PASS --wp-path /path/to/wp \\
      --db-host DBHOST --db-user DBUSER --db-pass DBPASS --db-name DBNAME \\
      --db-prefix wp_ [--isp-map isp-map.yaml] [--whois] [--json]
"""

import argparse
import json
import os
import re
import shlex
import sys
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
from wp_connect import (
    WPConnection, add_connection_args, print_banner, AuditResult,
    ok, warn, err, info, section, BOLD
)

try:
    from config_loader import load_config
    _HAS_CONFIG = True
except ImportError:
    _HAS_CONFIG = False


def _is_trusted(ip: str, trusted: list) -> bool:
    return any(ip.startswith(t) for t in trusted)


def _lookup_isp_from_map(ip: str, isp_map: dict) -> str:
    """Match IP against user-supplied CIDR prefix → ISP label map."""
    for prefix, label in isp_map.items():
        if ip.startswith(prefix):
            return label
    return ""


def _whois_lookup(wp: WPConnection, ip: str) -> str:
    """Do a whois lookup on the remote server (avoids local network restrictions)."""
    if not re.match(r"^[\d.:a-fA-F]+$", ip):
        return "invalid IP"
    result = wp.ssh(f"whois {shlex.quote(ip)} 2>/dev/null | grep -E 'OrgName|org-name|netname|descr|owner' | head -3")
    return result.strip()[:200] if result.strip() else "whois unavailable"


def load_isp_map(isp_map_path: str) -> dict:
    """Load optional ISP map YAML: { 'cidr_prefix': 'ISP name, location' }"""
    if not isp_map_path or not os.path.exists(isp_map_path):
        return {}
    try:
        import yaml
        with open(isp_map_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def extract_session_ips(wp: WPConnection, p: str) -> list:
    """Extract IPs from WP session_tokens usermeta."""
    raw = wp.db(
        f"SELECT u.user_login, u.user_email, m.meta_value "
        f"FROM {p}users u "
        f"JOIN {p}usermeta m ON u.ID=m.user_id "
        f"WHERE m.meta_key='session_tokens';"
    )
    entries = []
    for line in raw.splitlines():
        for ip in re.findall(r'"ip"\s*;s:\d+:"([^"]+)"', line) + re.findall(r'"ip":"([^"]+)"', line):
            entries.append({"ip": ip, "source": "wp_usermeta:session_tokens", "raw": line[:80]})
    return entries


def extract_log_ips(wp: WPConnection) -> list:
    """Parse debug.log and error_log for WP-Arsenal alert entries."""
    entries = []
    log_paths = [
        wp.wp("wp-content/debug.log"),
        "/var/log/php_errors.log",
        "/var/log/apache2/error.log",
        "/var/log/nginx/error.log",
    ]
    for path in log_paths:
        content = wp.sftp_read(path).decode("utf-8", "replace")
        if not content:
            continue
        for m in re.finditer(r"\[WP-ARSENAL\]\s+(honeypot|login-monitor)[^:]*:\s*.*?IP[:\s]+(\d[\d.]+)", content, re.IGNORECASE):
            entries.append({"ip": m.group(2), "source": f"error_log:{m.group(1).lower()}"})
        for m in re.finditer(r"\[WP-ARSENAL\]\s+\S+\s+from\s+(\d[\d.]+)", content):
            entries.append({"ip": m.group(1), "source": "error_log:wp-arsenal"})
    return entries


def build_profile(wp: WPConnection, args: argparse.Namespace) -> AuditResult:
    result = AuditResult("wp-attacker-profile")
    p = wp.db_prefix
    trusted  = getattr(args, "trusted_cidrs", []) or ["127.0.0.1", "::1"]
    isp_map  = load_isp_map(getattr(args, "isp_map", "") or "")
    do_whois = getattr(args, "whois", False)
    all_hits: list = []

    # ── 1. Session token IPs ──────────────────────────────────────────
    section("1. WP session_tokens IPs")
    for entry in extract_session_ips(wp, p):
        ip = entry["ip"]
        if _is_trusted(ip, trusted):
            continue
        isp = _lookup_isp_from_map(ip, isp_map)
        if not isp and do_whois:
            isp = _whois_lookup(wp, ip)
        warn(f"Session IP: {ip}  {('→ ' + isp) if isp else ''}")
        result.add("HIGH", "session-ip", f"{ip} | {isp}", entry.get("raw", ""))
        all_hits.append({"ip": ip, "isp": isp, "source": entry["source"]})

    # ── 2. Honeypot / login-monitor hits ─────────────────────────────
    section("2. Honeypot & Login Monitor hits")
    for entry in extract_log_ips(wp):
        ip = entry["ip"]
        if _is_trusted(ip, trusted):
            continue
        isp = _lookup_isp_from_map(ip, isp_map)
        if not isp and do_whois:
            isp = _whois_lookup(wp, ip)
        warn(f"Alert [{entry['source']}]: {ip}  {('→ ' + isp) if isp else ''}")
        result.add("HIGH", "alert-ip", f"{ip} | {isp}", entry["source"])
        all_hits.append({"ip": ip, "isp": isp, "source": entry["source"]})

    # ── 3. Rogue admin accounts ───────────────────────────────────────
    section("3. User accounts — suspicious flags")
    users = wp.db(
        f"SELECT u.ID, u.user_login, u.user_email, u.user_registered "
        f"FROM {p}users u "
        f"JOIN {p}usermeta m ON u.ID=m.user_id "
        f"WHERE m.meta_key='{p}capabilities' AND m.meta_value LIKE '%administrator%';"
    )
    for line in users.splitlines():
        if line.startswith("ID"):
            continue
        # Flag logins that look auto-generated or non-human
        if re.search(r'(admin\d+|backup|system_admin|wp_\w+|adm[il]n)', line, re.I):
            err(f"Suspicious admin account: {line}")
            result.add("CRITICAL", "rogue-admin", line[:100], f"{p}users")

    # ── 4. Deduplicated profile ───────────────────────────────────────
    seen: set = set()
    unique: list = []
    for h in all_hits:
        if h["ip"] not in seen:
            seen.add(h["ip"])
            unique.append(h)

    if unique:
        section("4. Attacker Profile Summary")
        print(f"\n{'═'*68}")
        print(BOLD("  ATTACKER IPs — for police / ISP abuse report"))
        print(f"{'═'*68}")
        for entry in unique:
            print(f"  IP:     {entry['ip']}")
            if entry.get("isp"):
                print(f"  ISP:    {entry['isp']}")
            print(f"  Found:  {entry['source']}")
            print()
        if not isp_map and not do_whois:
            info("Tip: use --isp-map isp-map.yaml to label IPs with ISP names,")
            info("     or --whois to auto-lookup via whois on the server.")
    else:
        ok("No attacker IPs found (check log paths and config)")

    result.stat("unique_ips", len(unique))
    result.stat("generated",  datetime.utcnow().isoformat() + "Z")
    result.stats["ips"] = unique

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WP-Arsenal: Build attacker IP profile for forensic reports",
    )
    add_connection_args(parser)
    parser.add_argument("--isp-map", dest="isp_map", default="",
                        help="Path to YAML file mapping CIDR prefixes → ISP names")
    parser.add_argument("--whois", action="store_true",
                        help="Run whois on each IP via SSH (slower but no map needed)")
    args = parser.parse_args()

    if _HAS_CONFIG:
        args = load_config(args)

    print_banner("WP-ATTACKER-PROFILE — Forensic IP Analysis")

    with WPConnection(args) as wp:
        result = build_profile(wp, args)

    result.print_summary()
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()
