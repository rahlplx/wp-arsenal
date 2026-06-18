#!/usr/bin/env python3
"""
wp-theme-audit.py — Security audit of WordPress themes
=======================================================
Scans active theme (and optionally all installed themes) for:
  - PHP malware patterns: eval/base64, shell execution, obfuscation
  - External URL calls from theme PHP (file_get_contents, curl)
  - Script injection in theme PHP/HTML output
  - Recently modified theme files (configurable window)
  - Unexpected file types in theme directory
  - Injected scripts in Customizer/theme options in the DB
  - Elementor postmeta injection (shortcodes planted in page content)

Usage:
  python scripts/security/wp-theme-audit.py --config config/config.yaml
  python scripts/security/wp-theme-audit.py --config config/config.yaml --all-themes
  python scripts/security/wp-theme-audit.py --config config/config.yaml --theme mytheme
  python scripts/security/wp-theme-audit.py --config config/config.yaml --days 30 --json
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wp_connect import (
    WPConnection, add_connection_args, print_banner, AuditResult,
    ok, warn, err, info, section
)

# ── Malware signature patterns ─────────────────────────────────────────────
# Format: (grep_pattern, severity, category, description)
THEME_SIGNATURES = [
    # Obfuscated code execution
    (r"eval\s*(\s*base64_decode",        "CRITICAL", "obfuscation",   "eval(base64_decode(...)) — classic PHP shell obfuscation"),
    (r"eval\s*(\s*gzinflate",            "CRITICAL", "obfuscation",   "eval(gzinflate(...)) — compressed PHP backdoor"),
    (r"eval\s*(\s*str_rot13",            "CRITICAL", "obfuscation",   "eval(str_rot13(...)) — ROT13 obfuscation"),
    (r"eval\s*(\s*gzdecode",             "CRITICAL", "obfuscation",   "eval(gzdecode(...)) — compressed backdoor"),
    (r"preg_replace\s*\(.*\/e['\"]",     "CRITICAL", "code-exec",     "preg_replace /e modifier — deprecated code execution"),
    (r"create_function\s*\(",            "HIGH",     "code-exec",     "create_function() — deprecated, commonly used in malware"),
    (r"assert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)", "CRITICAL", "backdoor", "assert() with user input — remote code execution backdoor"),
    # Shell execution
    (r"\bsystem\s*\(",                   "HIGH",     "shell-exec",    "system() — OS command execution"),
    (r"\bexec\s*\(",                     "HIGH",     "shell-exec",    "exec() — OS command execution"),
    (r"\bpassthru\s*\(",                 "HIGH",     "shell-exec",    "passthru() — OS command execution"),
    (r"\bshell_exec\s*\(",               "HIGH",     "shell-exec",    "shell_exec() — OS command execution"),
    (r"\bpopen\s*\(",                    "HIGH",     "shell-exec",    "popen() — OS command execution"),
    (r"\bproc_open\s*\(",                "HIGH",     "shell-exec",    "proc_open() — OS command execution"),
    # External file inclusion
    (r"file_get_contents\s*\(\s*['\"]https?://", "HIGH", "remote-include", "file_get_contents() with external URL in theme"),
    (r"include\s*\(\s*['\"]https?://",   "CRITICAL", "remote-include", "Remote file inclusion via include()"),
    (r"require\s*\(\s*['\"]https?://",   "CRITICAL", "remote-include", "Remote file inclusion via require()"),
    # wp-config.php access from theme
    (r"wp-config\.php",                  "HIGH",     "config-access", "Reference to wp-config.php from theme file"),
    # Backdoor input sources
    (r"\$_COOKIE\s*\[.*\]\s*\)",         "MEDIUM",   "user-input",    "Cookie value used directly — potential input for eval/include"),
    # Script injection
    (r"<script[^>]*src=['\"]https?://[^'\"]*['\"]", "HIGH", "script-inject", "Hardcoded external script tag in theme PHP"),
    (r"document\.write\s*\(",            "MEDIUM",   "script-inject", "document.write() — common in malware-injected JS"),
    # Hidden payload patterns
    (r"\$[a-z]{1,2}\s*=\s*\$[a-z]{1,2}\s*\(\s*\$[a-z]{1,2}", "MEDIUM", "obfuscation", "Variable function chaining — common in obfuscated malware"),
]

EXPECTED_THEME_EXTENSIONS = {
    ".php", ".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".webp",
    ".svg", ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".html", ".htm", ".txt", ".md", ".json", ".xml", ".map",
    ".mo", ".po", ".pot",   # translation files
}


def get_active_theme(wp: WPConnection) -> str:
    """Get the active theme slug from the DB (template option)."""
    p = wp.db_prefix
    row = wp.db(
        f"SELECT option_value FROM {p}options WHERE option_name='template' LIMIT 1;"
    )
    return row.strip().splitlines()[-1].strip() if row.strip() else ""


def get_installed_themes(wp: WPConnection) -> list[str]:
    """List all theme directory names in wp-content/themes/."""
    out = wp.ssh(
        f"ls -1 '{wp.wp('wp-content/themes')}' 2>/dev/null"
    )
    return [t.strip() for t in out.splitlines() if t.strip() and not t.startswith(".")]


def scan_theme_signatures(wp: WPConnection, theme_slug: str, result: AuditResult) -> int:
    """Grep theme directory for malware patterns. Returns finding count."""
    theme_dir = wp.wp(f"wp-content/themes/{theme_slug}")
    found = 0
    for pattern, severity, category, desc in THEME_SIGNATURES:
        matches = wp.ssh(
            f"grep -rIl --include='*.php' -E '{pattern}' '{theme_dir}' 2>/dev/null"
        )
        for fpath in matches.strip().splitlines():
            fpath = fpath.strip()
            if not fpath:
                continue
            # Get the matching line for context
            line = wp.ssh(
                f"grep -nI -m 1 -E '{pattern}' '{fpath}' 2>/dev/null | head -1"
            ).strip()
            err(f"  [{severity}] {desc}")
            err(f"    File: {fpath}")
            if line:
                err(f"    Line: {line[:120]}")
            result.add(severity, f"theme-{category}", f"{desc} in {fpath}", fpath)
            found += 1
    return found


def scan_recently_modified(wp: WPConnection, theme_slug: str, days: int, result: AuditResult) -> int:
    """Find theme PHP files modified within the last N days."""
    theme_dir = wp.wp(f"wp-content/themes/{theme_slug}")
    out = wp.ssh(
        f"find '{theme_dir}' -name '*.php' -mtime -{days} 2>/dev/null"
    )
    files = [f.strip() for f in out.splitlines() if f.strip()]
    if files:
        warn(f"  {len(files)} PHP file(s) modified in last {days} days:")
        for f in files[:20]:
            mtime = wp.ssh(f"stat -c '%y' '{f}' 2>/dev/null | cut -d' ' -f1").strip()
            info(f"    {mtime}  {f}")
            result.add("MEDIUM", "recently-modified",
                       f"PHP file modified {mtime}: {f}", f)
        if len(files) > 20:
            info(f"    ... and {len(files) - 20} more")
    return len(files)


def scan_unexpected_files(wp: WPConnection, theme_slug: str, result: AuditResult) -> int:
    """Find files with unexpected extensions in theme directory."""
    theme_dir = wp.wp(f"wp-content/themes/{theme_slug}")
    out = wp.ssh(
        f"find '{theme_dir}' -type f 2>/dev/null"
    )
    unexpected = []
    for f in out.strip().splitlines():
        f = f.strip()
        if not f:
            continue
        ext = os.path.splitext(f)[1].lower()
        if ext not in EXPECTED_THEME_EXTENSIONS and ext:
            unexpected.append(f)
    if unexpected:
        warn(f"  {len(unexpected)} unexpected file type(s) in theme:")
        for f in unexpected[:10]:
            info(f"    {f}")
            result.add("MEDIUM", "unexpected-file", f"Unexpected file in theme: {f}", f)
    return len(unexpected)


def scan_customizer_injection(wp: WPConnection, result: AuditResult) -> None:
    """Check theme_mods and customizer options for injected scripts."""
    p = wp.db_prefix
    rows = wp.db(
        f"SELECT option_name, option_value FROM {p}options "
        f"WHERE (option_name LIKE 'theme_mods_%' OR option_name = 'custom_css_post_id') "
        f"AND option_value REGEXP '<script|javascript:|eval\\\\(' LIMIT 20;"
    )
    if rows.strip() and "option_name" not in rows.strip().lower().split("\n")[0].lower():
        for line in rows.strip().splitlines():
            if not line.strip() or line.startswith("option_name"):
                continue
            parts = line.strip().split("\t", 1)
            if len(parts) >= 1:
                err(f"  Injected script in customizer option: {parts[0]}")
                result.add("CRITICAL", "customizer-injection",
                           f"Script/eval found in customizer option: {parts[0]}", "")


def scan_elementor_injection(wp: WPConnection, result: AuditResult) -> None:
    """Check Elementor page data in postmeta for injected scripts."""
    p = wp.db_prefix
    rows = wp.db(
        f"SELECT pm.post_id, pm.meta_value FROM {p}postmeta pm "
        f"WHERE pm.meta_key='_elementor_data' "
        f"AND pm.meta_value REGEXP '<script|javascript:|eval\\\\(' LIMIT 10;"
    )
    if rows.strip() and "post_id" not in rows.strip().lower().split("\n")[0]:
        for line in rows.strip().splitlines():
            if not line.strip() or line.startswith("post_id"):
                continue
            parts = line.strip().split("\t", 1)
            pid = parts[0] if parts else "?"
            err(f"  Injected script in Elementor data for post ID {pid}")
            result.add("CRITICAL", "elementor-injection",
                       f"Script/eval in Elementor data for post {pid}", "")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WP-Arsenal: Security audit of WordPress themes"
    )
    add_connection_args(parser)
    parser.add_argument("--theme", default="",
                        help="Specific theme slug to audit (default: active theme)")
    parser.add_argument("--all-themes", action="store_true",
                        help="Audit all installed themes, not just the active one")
    parser.add_argument("--days", type=int, default=14,
                        help="Flag PHP files modified within last N days (default: 14)")
    parser.add_argument("--skip-signatures", action="store_true",
                        help="Skip malware signature grep (faster, less thorough)")
    args = parser.parse_args()

    print_banner("WP-THEME-AUDIT — Theme Security Audit", args.dry_run)
    result = AuditResult("wp-theme-audit")

    with WPConnection(args) as wp:

        # Determine which themes to audit
        active_theme = get_active_theme(wp)
        if args.theme:
            themes_to_audit = [args.theme]
        elif args.all_themes:
            themes_to_audit = get_installed_themes(wp)
            info(f"Auditing all {len(themes_to_audit)} installed theme(s)")
        else:
            themes_to_audit = [active_theme] if active_theme else []

        if not themes_to_audit:
            err("No theme to audit — specify --theme or check DB for active theme")
            return

        info(f"Active theme: {active_theme}")
        result.stat("active_theme", active_theme)
        result.stat("themes_audited", len(themes_to_audit))

        for theme in themes_to_audit:
            is_active = " [ACTIVE]" if theme == active_theme else ""
            section(f"Theme: {theme}{is_active}")

            theme_dir = wp.wp(f"wp-content/themes/{theme}")
            if not wp.wp_exists(f"wp-content/themes/{theme}"):
                err(f"  Theme directory not found: {theme_dir}")
                result.add("HIGH", "theme-missing", f"Theme directory missing: {theme}", theme_dir)
                continue

            # Signature scan
            if not args.skip_signatures:
                info("  Scanning for malware signatures...")
                n = scan_theme_signatures(wp, theme, result)
                if n == 0:
                    ok(f"  No malware signatures found")

            # Recently modified files
            info(f"  Checking files modified in last {args.days} days...")
            m = scan_recently_modified(wp, theme, args.days, result)
            if m == 0:
                ok(f"  No recently modified PHP files")

            # Unexpected file types
            info("  Checking for unexpected file types...")
            u = scan_unexpected_files(wp, theme, result)
            if u == 0:
                ok("  No unexpected file types")

        # DB checks (active theme only)
        section("Database checks")
        info("  Scanning customizer/theme_mods for injected scripts...")
        scan_customizer_injection(wp, result)

        info("  Scanning Elementor page data for injected scripts...")
        scan_elementor_injection(wp, result)

        if not result.findings:
            ok("Theme audit complete — no issues found")

    result.print_summary()
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()
