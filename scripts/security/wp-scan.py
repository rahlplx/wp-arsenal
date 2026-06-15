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


def run_scan(wp: WPConnection, args: argparse.Namespace) -> AuditResult:
    result = AuditResult("wp-scan")

    # ── A. Non-standard root files ──────────────────────────────────────
    section("A. WP Root — unexpected files")
    root_files = wp.ssh(f"ls -1a '{wp.wp_path}/' 2>/dev/null")
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
    for fname in KNOWN_BAD_FILENAMES:
        hit = wp.ssh(
            f"find '{wp.wp_path}' -name '{fname}' -not -path '*/node_modules/*' 2>/dev/null"
        )
        if hit:
            for path in hit.splitlines():
                err(f"Known malware file: {path.strip()}")
                result.add("CRITICAL", "known-bad-file", fname, path.strip())
                found_bad.append(path.strip())
    if not found_bad:
        ok("No known bad filenames found")

    # ── C. PHP in uploads ──────────────────────────────────────────────
    section("C. PHP files in uploads/")
    uploads_php = wp.ssh(
        f"find '{wp.wp('wp-content/uploads')}' -name '*.php' 2>/dev/null | head -30"
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
        f"find '{wp.wp_path}' -name '*.php' -newer '{wp.wp_path}/wp-login.php' "
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
        hits = wp.ssh(
            f"grep -rl --include='*.php' -E '{pattern}' '{wp.wp_path}' 2>/dev/null | "
            f"grep -v '/node_modules/' | head -10"
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
        f"find '{wp.wp_path}' -maxdepth 2 -name '.*' -not -name '.htaccess' "
        f"-not -name '.git' 2>/dev/null"
    )
    if hidden.strip():
        for path in hidden.splitlines():
            warn(f"Hidden file: {path.strip()}")
            result.add("MEDIUM", "hidden-file", "Hidden file found", path.strip())
    else:
        ok("No unexpected hidden files")

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
