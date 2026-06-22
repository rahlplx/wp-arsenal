#!/usr/bin/env python3
"""
wp-scan.py — Fast WordPress malware surface scan
=================================================
Checks for known-bad files, suspicious PHP patterns, and basic indicators
of compromise. Designed to run in under 60 seconds for a typical site.

Usage:
  python wp-scan.py --host HOST --user USER --password PASS --wp-path /path/to/wp

Output:
  Colour-coded console summary + optional --json flag for machine-readable output
"""

import argparse
import json
import re
import shlex
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wp_connect import (
    WPConnection, add_connection_args, print_banner, AuditResult,
    ok, warn, err, info, section, RED, GREEN, YELLOW, CYAN, BOLD
)

# ── Known attacker signatures ──────────────────────────────────────────────
MALWARE_PATTERNS = [
    # Shell toolkits
    ("C99shell / R57",          r"c99shell|r57shell|FilesMan|b374k|WSO\s+Shell"),
    ("TFM / Nyx toolkit",       r"Nyx_Fallaga|TFMshell|GhostShell|AnonymousFox"),
    ("eval+base64",             r"eval\s*\(\s*base64_decode"),
    ("eval+gzinflate",          r"eval\s*\(\s*gzinflate"),
    ("eval+str_rot13",          r"eval\s*\(\s*str_rot13"),
    ("assert execution",        r'assert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)'),
    ("preg_replace /e flag",    r"preg_replace\s*\(\s*['\"]/.*/e"),
    ("system/exec injection",   r'\b(system|exec|passthru|shell_exec|popen)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'),
    ("create_function",         r"create_function\s*\("),
    ("obfuscated variable",     r'\$[a-zA-Z0-9_]{1,3}\s*=\s*\$[a-zA-Z0-9_]{1,3}\s*\(\s*["\'][a-zA-Z0-9+/]{20,}'),
    ("mail spam injector",      r'mail\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'),
    ("iframe inject",           r'<iframe[^>]+src=["\']http'),
    ("script inject",           r'<script[^>]+src=["\']http[^"\']+\.(ru|cn|tk|pw|xyz|top)'),
    ("hex-encoded PHP",         r"\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}"),
    ("auto_prepend in PHP",     r"auto_prepend_file\s*="),
]

# ── Non-standard WP root files (anything not in this list = suspicious) ───
WP_ROOT_WHITELIST = {
    "wp-activate.php","wp-blog-header.php","wp-comments-post.php",
    "wp-config.php","wp-config-sample.php","wp-cron.php","wp-links-opml.php",
    "wp-load.php","wp-login.php","wp-mail.php","wp-settings.php",
    "wp-signup.php","wp-trackback.php","xmlrpc.php","index.php",
    "favicon.ico","robots.txt","readme.html","license.txt",
    ".htaccess","wp-content","wp-includes","wp-admin",
}

# ── Attacker-known filenames ───────────────────────────────────────────────
KNOWN_BAD_FILENAMES = [
    "offline.php","functions-interpreter.php","header-repository.php",
    "index-more.php","footer-class.php","cache-handler.php","wp-term-meta.php",
    "sso.php","site-compat.php","http-insights.php","wp-temp.php",
    "install.php","test.php","shell.php","cmd.php","up.php","upload.php",
    "wso.php","c99.php","r57.php","b374k.php","adminer.php","filemanager.php",
    ".ico.php",".jpg.php",".gif.php",".png.php",
]

# ── Dangerous tools left in webroot (WPScan-equivalent checks) ─────────────
DANGEROUS_WEBROOT_FILES = [
    ("emergency.php",          "CRITICAL", "Emergency password reset script in webroot"),
    ("searchreplacedb2.php",   "CRITICAL", "Search & Replace DB tool in webroot"),
    ("wp-config.php.bak",      "CRITICAL", "wp-config backup exposed"),
    ("adminer.php",            "CRITICAL", "Adminer DB admin tool in webroot"),
    ("phpinfo.php",            "HIGH",     "phpinfo() disclosure in webroot"),
    ("info.php",               "HIGH",     "phpinfo() disclosure in webroot"),
]

# ── wp-config.php backup filename variants (from Wordpresscan research) ─────
WP_CONFIG_BACKUPS = [
    "wp-config.php~","wp-config.php.save",".wp-config.php.bck",
    "wp-config.php.bck",".wp-config.php.swp","wp-config.php.swp",
    "wp-config.php.swo","wp-config.php_bak","wp-config.bak",
    "wp-config.php.bak","wp-config.save","wp-config.old",
    "wp-config.php.old","wp-config.php.orig","wp-config.orig",
    "wp-config.php.original","wp-config.original","wp-config.txt",
    "wp-config.php.txt","wp-config.backup","wp-config.php.backup",
    "wp-config.copy","wp-config.php.copy","wp-config.tmp",
    "wp-config.php.tmp","wp-config.zip","wp-config.php.zip",
    "wp-config.db","wp-config.php.db","wp-config.dat",
    "wp-config.php.dat","wp-config.tar.gz","wp-config.php.tar.gz",
    "wp-config.back","wp-config.php.back","wp-config.test",
    "wp-config.php.test","wp-config.php.1","wp-config.php.2","wp-config.php.3",
    "wp-config.php._inc","wp-config_inc",
]

# ── Directory listing checks (WPScan checks all 5) ─────────────────────────
DIR_LISTING_PATHS = [
    ("wp-content/uploads/",  "Uploads directory listing exposes user files"),
    ("wp-content/plugins/",  "Plugins directory listing reveals installed plugins"),
    ("wp-content/themes/",   "Themes directory listing reveals installed themes"),
    ("wp-includes/",         "wp-includes directory listing exposes core internals"),
    ("wp-admin/",            "wp-admin directory listing"),
]


def run_scan(wp: WPConnection, args: argparse.Namespace) -> AuditResult:
    result = AuditResult("wp-scan")

    # ── A. Non-standard root files ──────────────────────────────────────
    section("A. WP Root — unexpected files")
    root_files = wp.ssh(f"ls -1a {shlex.quote(wp.wp_path + '/')} 2>/dev/null")
    rogue_root = []
    for f in root_files.splitlines():
        f = f.strip()
        if f in (".", "..") or f in WP_ROOT_WHITELIST:
            continue
        if f.endswith(".php") or f.startswith(".") and f not in (".htaccess",):
            rogue_root.append(f)
    if rogue_root:
        for f in rogue_root:
            err(f"Unexpected file in WP root: {f}")
            result.add("HIGH", "rogue-root-file", f, wp.wp(f))
    else:
        ok("WP root clean")

    # ── B. Known bad filenames ──────────────────────────────────────────
    section("B. Known attacker filenames")
    found_bad = []
    # Single find with OR predicates instead of 26 separate SSH round-trips
    name_clauses = " -o ".join(f"-name {shlex.quote(f)}" for f in KNOWN_BAD_FILENAMES)
    hits_raw = wp.ssh(
        f"find {shlex.quote(wp.wp_path)} \\( {name_clauses} \\) "
        f"-not -path '*/node_modules/*' 2>/dev/null"
    )
    if hits_raw.strip():
        for path in hits_raw.splitlines():
            path = path.strip()
            if path:
                fname = os.path.basename(path)
                err(f"Known malware file: {path}")
                result.add("CRITICAL", "known-bad-file", fname, path)
                found_bad.append(path)
    if not found_bad:
        ok("No known bad filenames found")

    # ── C. PHP in uploads ──────────────────────────────────────────────
    section("C. PHP files in uploads/")
    uploads_php = wp.ssh(
        f"find {shlex.quote(wp.wp('wp-content/uploads'))} -name '*.php' 2>/dev/null | head -30"
    )
    if uploads_php.strip():
        for path in uploads_php.splitlines():
            err(f"PHP in uploads: {path.strip()}")
            result.add("CRITICAL", "php-in-uploads", "PHP file in uploads directory", path.strip())
    else:
        ok("No PHP files in uploads/")

    # ── D. PHP files modified in last 14 days ──────────────────────────
    section("D. Recently modified PHP files (14 days)")
    recent = wp.ssh(
        f"find {shlex.quote(wp.wp_path)} -name '*.php' "
        f"-newer {shlex.quote(wp.wp_path + '/wp-login.php')} "
        f"-not -path '*/node_modules/*' -mtime -14 2>/dev/null | head -50"
    )
    if recent.strip():
        lines = [l.strip() for l in recent.splitlines() if l.strip()]
        for path in lines:
            warn(f"Recently modified: {path}")
            result.add("MEDIUM", "recent-php-change", "PHP file modified in last 14 days", path)
        result.stat("recently_modified_php", len(lines))
    else:
        ok("No PHP files modified in last 14 days")

    # ── E. Malware signatures ───────────────────────────────────────────
    section("E. Malware signatures (grep)")
    for name, pattern in MALWARE_PATTERNS:
        # Pass pattern via env var so bash never sees $ signs from the regex —
        # shell expansion of $_(POST|...) would silently break the grep match.
        hits = wp.ssh(
            f"WP_PAT={shlex.quote(pattern)} grep -rl --include='*.php' -E \"$WP_PAT\" "
            f"{shlex.quote(wp.wp_path)} 2>/dev/null | grep -v '/node_modules/' | head -10"
        )
        if hits.strip():
            for path in hits.splitlines():
                err(f"[{name}] {path.strip()}")
                result.add("CRITICAL", "malware-signature", name, path.strip())
        else:
            info(f"Clean: {name}")

    # ── F. .htaccess anomalies ─────────────────────────────────────────
    section("F. .htaccess checks")
    htaccess = wp.sftp_read(wp.wp(".htaccess")).decode("utf-8", "replace")
    dangerous_htaccess = [
        "auto_prepend_file", "auto_append_file", "AddHandler",
        "SetHandler", "php_value auto_prepend",
        "Options +Indexes", "Options Indexes",
    ]
    ht_issues = [d for d in dangerous_htaccess if d.lower() in htaccess.lower()]
    if ht_issues:
        for issue in ht_issues:
            err(f".htaccess contains: {issue}")
            result.add("HIGH", "htaccess-anomaly", issue, wp.wp(".htaccess"))
    else:
        ok(".htaccess looks clean")

    # ── G. SSH authorized_keys ─────────────────────────────────────────
    section("G. SSH authorized_keys")
    auth_keys = wp.ssh("cat ~/.ssh/authorized_keys 2>/dev/null")
    if auth_keys.strip():
        lines = [l for l in auth_keys.splitlines() if l.strip() and not l.startswith("#")]
        warn(f"{len(lines)} SSH key(s) found in authorized_keys")
        for k in lines:
            result.add("HIGH", "ssh-authorized-key", k[:80], "~/.ssh/authorized_keys")
    else:
        ok("No SSH authorized_keys")

    # ── H. Hidden files ────────────────────────────────────────────────
    section("H. Hidden files in WP root")
    hidden = wp.ssh(
        f"find {shlex.quote(wp.wp_path)} -maxdepth 2 -name '.*' -not -name '.htaccess' "
        f"-not -name '.git' 2>/dev/null"
    )
    if hidden.strip():
        for path in hidden.splitlines():
            warn(f"Hidden file: {path.strip()}")
            result.add("MEDIUM", "hidden-file", "Hidden file found", path.strip())
    else:
        ok("No unexpected hidden files")

    # ── I. wp-config.php backup files (36 variants) ───────────────────
    section("I. wp-config.php backup exposure")
    config_backups_found = []
    for fname in WP_CONFIG_BACKUPS:
        if wp.wp_exists(fname):
            err(f"wp-config backup exposed: {fname}")
            result.add("CRITICAL", "config-backup-exposed", f"wp-config backup: {fname}", wp.wp(fname))
            config_backups_found.append(fname)
    if not config_backups_found:
        ok("No wp-config backup files found")

    # ── J. Dangerous tools in webroot ──────────────────────────────────
    section("J. Dangerous tools in webroot")
    tools_found = []
    for fname, sev, detail in DANGEROUS_WEBROOT_FILES:
        if wp.wp_exists(fname):
            err(f"{detail}: {fname}")
            result.add(sev, "dangerous-webroot-tool", detail, wp.wp(fname))
            tools_found.append(fname)
    # Also check upload dir for SQL dump (WPScan finding)
    if wp.wp_exists("wp-content/uploads/dump.sql"):
        err("SQL dump found in uploads directory!")
        result.add("CRITICAL", "sql-dump-in-uploads", "Database dump publicly accessible", wp.wp("wp-content/uploads/dump.sql"))
        tools_found.append("uploads/dump.sql")
    if not tools_found:
        ok("No dangerous tools found in webroot")

    # ── K. Directory listing checks (all 5 WP dirs) ────────────────────
    section("K. Directory listing exposure")
    if wp.site_url:
        dir_listing_found = []
        for rel_path, detail in DIR_LISTING_PATHS:
            url = f"{wp.site_url.rstrip('/')}/{rel_path}"
            body = wp.http_body(url)
            if body and ("Index of" in body or "Directory listing" in body):
                err(f"Directory listing enabled: {rel_path}")
                result.add("HIGH", "directory-listing", detail, url)
                dir_listing_found.append(rel_path)
        if not dir_listing_found:
            ok("No directory listing found on any WP directory")
    else:
        info("--site-url not provided — skipping directory listing checks")

    # ── L. readme.html version disclosure ──────────────────────────────
    section("L. Version disclosure")
    if wp.site_url:
        for readme_file in ["readme.html", "olvasdel.html", "liesmich.html"]:
            url = f"{wp.site_url.rstrip('/')}/{readme_file}"
            body = wp.http_body(url)
            if body and "wordpress" in body.lower():
                ver_match = re.search(r"Version\s+([\d.]+)", body)
                version = ver_match.group(1) if ver_match else "unknown"
                warn(f"{readme_file} is publicly accessible (WP version: {version})")
                result.add("MEDIUM", "version-disclosure", f"WP version {version} via {readme_file}", url)
                break
        else:
            ok("No version disclosure via readme files")

    # ── M. robots.txt — Disallow path leakage ──────────────────────────
    section("M. robots.txt analysis")
    if wp.site_url:
        robots_body = wp.http_body(f"{wp.site_url.rstrip('/')}/robots.txt")
        if robots_body:
            disallowed = [l.strip() for l in robots_body.splitlines()
                          if l.strip().lower().startswith("disallow:") and l.strip() != "Disallow:"]
            if disallowed:
                info(f"robots.txt Disallow entries ({len(disallowed)}):")
                for entry in disallowed:
                    path = entry.split(":", 1)[1].strip()
                    info(f"  {path}")
                    if any(x in path.lower() for x in ["backup", "admin", "config", "install", "db", "sql"]):
                        warn(f"Sensitive path in robots.txt: {path}")
                        result.add("LOW", "robots-sensitive-path", f"Sensitive path disclosed: {path}", f"{wp.site_url}/robots.txt")
            else:
                ok("robots.txt has no Disallow entries")
        else:
            info("No robots.txt found")

    # ── Stats ──────────────────────────────────────────────────────────
    criticals = sum(1 for f in result.findings if f["severity"] == "CRITICAL")
    highs     = sum(1 for f in result.findings if f["severity"] == "HIGH")
    result.stat("critical_findings", criticals)
    result.stat("high_findings", highs)

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WP-Arsenal: Fast WordPress malware surface scan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_connection_args(parser)
    args = parser.parse_args()

    print_banner("WP-SCAN — Fast Malware Surface Scan", args.dry_run)

    with WPConnection(args) as wp:
        result = run_scan(wp, args)

    result.print_summary()

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))

    # Exit non-zero if any critical/high findings
    criticals = sum(1 for f in result.findings if f["severity"] in ("CRITICAL","HIGH"))
    sys.exit(1 if criticals else 0)


if __name__ == "__main__":
    main()
