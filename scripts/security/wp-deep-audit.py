#!/usr/bin/env python3
"""
wp-deep-audit.py — Comprehensive 8-domain WordPress security audit
===================================================================
Covers: Filesystem, Malware, Database, WP Config, Plugins/Themes,
        Server/Cron, Network/DNS, Logs

Takes ~3-8 minutes per site (MySQL queries + grep scans).
Produces a full incident-quality report.

Usage:
  python wp-deep-audit.py \\
      --host HOST --user USER --password PASS --wp-path /path/to/wp \\
      --db-host DBHOST --db-user DBUSER --db-pass DBPASS --db-name DBNAME \\
      --db-prefix wp_ --site-url https://example.com
"""

import argparse
import json
import shlex
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
from wp_connect import (
    WPConnection, add_connection_args, print_banner, AuditResult,
    ok, warn, err, info, section, BOLD, RED, YELLOW, CYAN, DIM
)

# ── Malware signatures ─────────────────────────────────────────────────────
SIGNATURES = [
    ("C99 / R57 shell",        r"c99shell|r57shell|FilesMan|b374k|WSO\s+Shell"),
    ("TFM / Nyx toolkit",      r"Nyx_Fallaga|TFMshell|GhostShell|AnonymousFox"),
    ("eval+base64",            r"eval\s*\(\s*base64_decode"),
    ("eval+gzinflate",         r"eval\s*\(\s*gzinflate"),
    ("eval+str_rot13",         r"eval\s*\(\s*str_rot13"),
    ("assert $_REQUEST",       r'assert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)'),
    ("preg_replace /e",        r"preg_replace\s*\(\s*['\"]/.*/e"),
    ("system/exec from $_",    r'\b(system|exec|passthru|shell_exec|popen)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'),
    ("create_function",        r"create_function\s*\("),
    ("mail spam injector",     r'mail\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'),
    ("iframe inject",          r'<iframe[^>]+src=["\']http'),
    ("script inject ru/cn",   r'<script[^>]+src=["\']http[^"\']+\.(ru|cn|tk|pw|xyz|top)'),
    ("hex obfuscation",        r"\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){4,}"),
    ("auto_prepend_file",      r"auto_prepend_file\s*="),
]


def domain_a_filesystem(wp: WPConnection, r: AuditResult) -> None:
    """A. Filesystem analysis."""
    section("DOMAIN A — Filesystem")

    # Hidden files in WP root
    hidden = wp.ssh(
        f"find {shlex.quote(wp.wp_path)} -maxdepth 2 -name '.*' "
        f"-not -name '.htaccess' -not -name '.git' 2>/dev/null"
    )
    for path in [p.strip() for p in hidden.splitlines() if p.strip()]:
        warn(f"Hidden file: {path}")
        r.add("MEDIUM", "hidden-file", "Hidden file", path)

    # PHP files modified last 14 days
    recent = wp.ssh(
        f"find {shlex.quote(wp.wp_path)} -name '*.php' -mtime -14 "
        f"-not -path '*/node_modules/*' 2>/dev/null | head -50"
    )
    recent_list = [p.strip() for p in recent.splitlines() if p.strip()]
    r.stat("php_modified_14d", len(recent_list))
    if recent_list:
        warn(f"{len(recent_list)} PHP files modified in last 14 days")
        for path in recent_list[:10]:
            r.add("MEDIUM", "recent-modification", "PHP modified < 14 days", path)

    # PHP in uploads
    uploads_php = wp.ssh(
        f"find {shlex.quote(wp.wp('wp-content/uploads'))} -name '*.php' 2>/dev/null"
    )
    for path in [p.strip() for p in uploads_php.splitlines() if p.strip()]:
        err(f"PHP in uploads: {path}")
        r.add("CRITICAL", "php-in-uploads", "PHP file in uploads", path)

    # World-writable files
    ww = wp.ssh(
        f"find {shlex.quote(wp.wp_path)} -perm -o+w -not -path '*/.git/*' 2>/dev/null | head -20"
    )
    for path in [p.strip() for p in ww.splitlines() if p.strip()]:
        err(f"World-writable: {path}")
        r.add("HIGH", "world-writable", "World-writable file", path)

    # SSH authorized_keys
    auth_keys = wp.ssh("cat ~/.ssh/authorized_keys 2>/dev/null")
    if auth_keys.strip():
        keys = [k for k in auth_keys.splitlines() if k.strip() and not k.startswith("#")]
        for k in keys:
            r.add("HIGH", "ssh-key", "SSH authorized key", k[:80])
        warn(f"{len(keys)} SSH authorized key(s) found")
    else:
        ok("No SSH authorized_keys")

    ok("Domain A complete")


def domain_b_malware(wp: WPConnection, r: AuditResult) -> None:
    """B. Malware signature scan."""
    section("DOMAIN B — Malware Signatures")
    for name, pattern in SIGNATURES:
        hits = wp.ssh(
            f"WP_PAT={shlex.quote(pattern)} grep -rl --include='*.php' -E \"$WP_PAT\" "
            f"'{wp.wp_path}' 2>/dev/null | grep -v '/node_modules/' | head -5"
        )
        if hits.strip():
            for path in hits.splitlines():
                err(f"[{name}] {path.strip()}")
                r.add("CRITICAL", "malware-signature", name, path.strip())
        else:
            info(f"Clean: {name}")
    ok("Domain B complete")


def domain_c_database(wp: WPConnection, r: AuditResult) -> None:
    """C. Database audit."""
    section("DOMAIN C — Database")
    p = wp.db_prefix

    # Admin users
    admins = wp.db(
        f"SELECT ID, user_login, user_email, user_registered FROM {p}users "
        f"WHERE ID IN (SELECT user_id FROM {p}usermeta WHERE meta_key='{p}capabilities' "
        f"AND meta_value LIKE '%administrator%');"
    )
    info(f"Admin accounts:\n{admins}")
    if admins:
        lines = [l for l in admins.splitlines() if l.strip() and not l.startswith("ID")]
        r.stat("admin_count", len(lines))
        for line in lines:
            r.add("INFO", "admin-user", "WordPress admin account", line[:120])

    # Session IPs (attacker fingerprinting)
    sessions = wp.db(
        f"SELECT user_login, meta_value FROM {p}users u "
        f"JOIN {p}usermeta m ON u.ID=m.user_id "
        f"WHERE m.meta_key='session_tokens' LIMIT 5;"
    )
    if sessions:
        info(f"Active sessions found (check for foreign IPs)")
        r.add("INFO", "active-sessions", "WP session data (check IPs)", sessions[:200])

    # Critical options
    critical_opts = [
        "siteurl", "home", "admin_email", "blogname",
        "active_plugins", "template", "stylesheet",
    ]
    for opt in critical_opts:
        val = wp.db(
            f"SELECT option_value FROM {p}options WHERE option_name='{opt}' LIMIT 1;"
        )
        info(f"  {opt}: {val[:80] if val else '(empty)'}")

    # Rank Math redirections (known attacker abuse vector)
    rm_count = wp.db(
        f"SELECT COUNT(*) FROM {p}rank_math_redirections;"
    )
    _rm_lines = [l.strip() for l in rm_count.splitlines() if l.strip().isdigit()]
    if _rm_lines and int(_rm_lines[-1]) > 50:
        warn(f"Rank Math has {_rm_lines[-1]} redirections — check for spam")
        r.add("MEDIUM", "rank-math-redirections", f"{rm_count.strip()} redirections", "")

    # Injected scripts in post meta
    inject_check = wp.db(
        f"SELECT COUNT(*) FROM {p}postmeta "
        f"WHERE meta_value LIKE '%<script%' OR meta_value LIKE '%eval(%';"
    )
    if inject_check and inject_check.strip() not in ("0", ""):
        err(f"Injected scripts found in postmeta: {inject_check.strip()} rows")
        r.add("CRITICAL", "db-injection", "Script injection in postmeta", "")

    ok("Domain C complete")


def domain_d_wpconfig(wp: WPConnection, r: AuditResult) -> None:
    """D. WP Config & server config."""
    section("DOMAIN D — WP Config / Server")

    # wp-config.php
    wpconfig = wp.sftp_read(wp.wp("wp-config.php")).decode("utf-8", "replace")
    if wpconfig:
        if "DB_PASSWORD" not in wpconfig:
            r.add("HIGH", "wpconfig", "wp-config.php missing DB_PASSWORD", wp.wp("wp-config.php"))
        if "define( 'WP_DEBUG', true" in wpconfig:
            warn("WP_DEBUG is enabled — may leak paths/errors")
            r.add("MEDIUM", "debug-enabled", "WP_DEBUG=true in production", wp.wp("wp-config.php"))
        if "define( 'DISALLOW_FILE_EDIT'" not in wpconfig:
            warn("DISALLOW_FILE_EDIT not set — theme editor accessible")
            r.add("MEDIUM", "file-edit-enabled", "DISALLOW_FILE_EDIT not set", wp.wp("wp-config.php"))
        ok("wp-config.php read successfully")
    else:
        err("Cannot read wp-config.php")
        r.add("HIGH", "wpconfig-unreadable", "wp-config.php unreadable", wp.wp("wp-config.php"))

    # PHP version
    php_version = wp.ssh("php -v 2>/dev/null | head -1")
    info(f"PHP CLI: {php_version}")
    r.stat("php_version", php_version.split()[1] if php_version else "unknown")

    # auto_prepend_file in php.ini
    auto_prepend = wp.ssh("php -r 'echo ini_get(\"auto_prepend_file\");' 2>/dev/null")
    if auto_prepend.strip():
        err(f"auto_prepend_file is set: {auto_prepend}")
        r.add("CRITICAL", "auto-prepend", "auto_prepend_file set in PHP config", auto_prepend.strip())

    # WP debug log
    debug_log = wp.wp("wp-content/debug.log")
    if wp.wp_exists("wp-content/debug.log"):
        size = wp.ssh(f"stat -c '%s' {shlex.quote(debug_log)} 2>/dev/null")
        warn(f"debug.log exists ({size} bytes) — publicly accessible")
        r.add("MEDIUM", "debug-log", "WP debug log is publicly accessible", debug_log)

    ok("Domain D complete")


def domain_e_plugins(wp: WPConnection, r: AuditResult) -> None:
    """E. Plugin/theme audit."""
    section("DOMAIN E — Plugins & Themes")

    # All installed plugins
    plugins = wp.ssh(f"ls -1 {shlex.quote(wp.wp('wp-content/plugins') + '/')} 2>/dev/null")
    plugin_list = [p.strip() for p in plugins.splitlines() if p.strip() and p.strip() not in (".","..",".htaccess","index.php")]
    r.stat("plugin_count", len(plugin_list))
    info(f"Installed plugins ({len(plugin_list)}): {', '.join(plugin_list)}")

    # Check for eval/base64 in plugin files
    for plugin in plugin_list:
        plugin_path = wp.wp(f"wp-content/plugins/{plugin}")
        hits = wp.ssh(
            f"grep -rl --include='*.php' -E 'eval\\s*\\(\\s*base64_decode|eval\\s*\\(\\s*gzinflate' "
            f"{shlex.quote(plugin_path)} 2>/dev/null | head -3"
        )
        if hits.strip():
            err(f"Obfuscated PHP in plugin: {plugin}")
            for path in hits.splitlines():
                r.add("CRITICAL", "obfuscated-plugin", f"Obfuscated PHP in {plugin}", path.strip())

    # Kadence theme integrity check
    kadence_path = wp.wp("wp-content/themes/kadence")
    if wp.wp_exists("wp-content/themes/kadence"):
        unexpected = wp.ssh(
            f"find {shlex.quote(kadence_path)} -name '*.php' "
            f"-newer {shlex.quote(kadence_path + '/style.css')} "
            f"-mtime -30 2>/dev/null | head -10"
        )
        if unexpected.strip():
            warn(f"Kadence has recently modified PHP files:")
            for path in unexpected.splitlines():
                warn(f"  {path.strip()}")
                r.add("HIGH", "theme-modified", "Theme PHP modified recently", path.strip())
        else:
            ok("Kadence theme looks unmodified")

    ok("Domain E complete")


def domain_f_server_cron(wp: WPConnection, r: AuditResult) -> None:
    """F. Server / cron / processes."""
    section("DOMAIN F — Server & Cron")

    # Crontab
    crontab = wp.ssh("crontab -l 2>/dev/null")
    if crontab.strip():
        info(f"Crontab:\n{crontab}")
        suspicious = [l for l in crontab.splitlines()
                      if any(x in l for x in ["wget","curl","base64","eval","php -r"])]
        for line in suspicious:
            err(f"Suspicious cron: {line}")
            r.add("HIGH", "suspicious-cron", "Suspicious cron job", line)
    else:
        ok("No crontab entries")

    # Running PHP processes
    php_procs = wp.ssh("ps aux 2>/dev/null | grep php | grep -v grep | head -10")
    if php_procs:
        info(f"PHP processes running:\n{php_procs}")

    # /tmp PHP files
    tmp_php = wp.ssh("find /tmp /var/tmp -name '*.php' 2>/dev/null")
    for path in [p.strip() for p in tmp_php.splitlines() if p.strip()]:
        err(f"PHP file in /tmp: {path}")
        r.add("HIGH", "php-in-tmp", "PHP file in /tmp — staging area", path)

    ok("Domain F complete")


def domain_g_network(wp: WPConnection, r: AuditResult) -> None:
    """G. Network / DNS."""
    section("DOMAIN G — Network & DNS")

    if not wp.site_url:
        info("--site-url not provided, skipping HTTP checks")
        return

    # HTTP status of homepage
    code = wp.http_code(wp.site_url)
    if code == "200":
        ok(f"Homepage returns HTTP 200")
    else:
        warn(f"Homepage returns HTTP {code}")
        r.add("MEDIUM", "http-status", f"Homepage returns {code}", wp.site_url)

    # wp-login.php accessibility
    login_code = wp.http_code(f"{wp.site_url}/wp-login.php")
    info(f"wp-login.php: HTTP {login_code}")

    # xmlrpc.php
    xmlrpc_code = wp.http_code(f"{wp.site_url}/xmlrpc.php")
    if xmlrpc_code == "200":
        warn("xmlrpc.php accessible (brute-force attack surface)")
        r.add("MEDIUM", "xmlrpc-open", "xmlrpc.php is publicly accessible", f"{wp.site_url}/xmlrpc.php")
    else:
        ok(f"xmlrpc.php: {xmlrpc_code} (blocked)")

    # SSL cert expiry
    domain = wp.site_url.replace("https://","").replace("http://","").split("/")[0]
    cert_expiry = wp.ssh(
        f"echo | openssl s_client -servername {shlex.quote(domain)} "
        f"-connect {shlex.quote(domain + ':443')} 2>/dev/null "
        f"| openssl x509 -noout -enddate 2>/dev/null"
    )
    info(f"SSL cert expiry: {cert_expiry}")

    ok("Domain G complete")


def domain_h_logs(wp: WPConnection, r: AuditResult) -> None:
    """H. Log analysis."""
    section("DOMAIN H — Logs & Access Patterns")

    # Recent access log entries with POST to PHP files
    access_log_paths = [
        "/var/log/apache2/access.log",
        "/var/log/nginx/access.log",
        f"{wp.wp_path}/../logs/access.log",
    ]
    for log_path in access_log_paths:
        exists = wp.ssh(f"test -f {shlex.quote(log_path)} && echo Y || echo N")
        if exists == "Y":
            post_hits = wp.ssh(
                f"grep 'POST.*\\.php' {shlex.quote(log_path)} 2>/dev/null | tail -20"
            )
            if post_hits.strip():
                info(f"Recent POST to PHP (from {log_path}):\n{post_hits[:500]}")
            break

    # WP admin login attempts (from DB)
    login_log = wp.db(
        f"SELECT option_value FROM {wp.db_prefix}options "
        f"WHERE option_name LIKE '%login_log%' OR option_name LIKE '%failed_login%' LIMIT 3;"
    )
    if login_log:
        info(f"Login log data: {login_log[:200]}")

    ok("Domain H complete")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WP-Arsenal: Comprehensive 8-domain WordPress security audit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_connection_args(parser)
    args = parser.parse_args()

    print_banner(
        f"WP-DEEP-AUDIT — 8-Domain Security Audit\n  Target: {args.host}",
        args.dry_run
    )

    result = AuditResult("wp-deep-audit")

    with WPConnection(args) as wp:
        domain_a_filesystem(wp, result)
        domain_b_malware(wp, result)
        domain_c_database(wp, result)
        domain_d_wpconfig(wp, result)
        domain_e_plugins(wp, result)
        domain_f_server_cron(wp, result)
        domain_g_network(wp, result)
        domain_h_logs(wp, result)

    result.stat("audit_timestamp", datetime.utcnow().isoformat() + "Z")
    result.print_summary()

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()
