#!/usr/bin/env python3
"""
wp-forensics.py — Full forensic evidence collection
====================================================
Collects and archives forensic evidence from a compromised WordPress site:
  - All malware files (copies, not deletes)
  - Server logs (access.log, error.log)
  - wp-config.php (redacted passwords)
  - Crontab
  - Running processes snapshot
  - Database dump of critical tables
  - WP session tokens (attacker IPs)
  - Bash history

Outputs a timestamped tar.gz archive on the server, plus a local copy
via SFTP if --output-local is specified.

Usage:
  python wp-forensics.py \\
      --host HOST --user USER --password PASS --wp-path /path/to/wp \\
      --db-host DBHOST --db-user DBUSER --db-pass DBPASS --db-name DBNAME \\
      --db-prefix wp_ --output-local ./evidence/
"""

import argparse
import json
import sys
import os
import stat
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
from wp_connect import (
    WPConnection, add_connection_args, print_banner, AuditResult,
    ok, warn, err, info, section
)

MALWARE_PATTERNS = [
    r"eval\s*\(\s*base64_decode",
    r"eval\s*\(\s*gzinflate",
    r"c99shell|r57shell|FilesMan",
    r"Nyx_Fallaga|TFMshell",
    r'assert\s*\(\s*\$_(POST|GET|REQUEST)',
    r'system\s*\(\s*\$_(GET|POST|REQUEST)',
]


def collect_evidence(wp: WPConnection, args: argparse.Namespace) -> AuditResult:
    result = AuditResult("wp-forensics")
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    evidence_dir = f"/tmp/wp-evidence-{ts}"
    archive_path = f"/tmp/wp-evidence-{ts}.tar.gz"

    # ── Setup ──────────────────────────────────────────────────────────
    section("1. Setup evidence directory")
    wp.ssh(f"mkdir -p '{evidence_dir}/malware' '{evidence_dir}/logs' "
           f"'{evidence_dir}/config' '{evidence_dir}/db'")
    ok(f"Evidence dir: {evidence_dir}")

    # ── 2. Collect malware files ───────────────────────────────────────
    section("2. Copy malware files (evidence preservation)")
    malware_found = 0
    for pattern in MALWARE_PATTERNS:
        hits = wp.ssh(
            f"grep -rl --include='*.php' -E '{pattern}' '{wp.wp_path}' 2>/dev/null | "
            f"grep -v '/node_modules/' | head -20"
        )
        for path in [p.strip() for p in hits.splitlines() if p.strip()]:
            wp.ssh(f"cp '{path}' '{evidence_dir}/malware/' 2>/dev/null")
            malware_found += 1
            info(f"Preserved: {path}")

    # PHP in uploads
    uploads_php = wp.ssh(
        f"find '{wp.wp('wp-content/uploads')}' -name '*.php' 2>/dev/null"
    )
    for path in [p.strip() for p in uploads_php.splitlines() if p.strip()]:
        wp.ssh(f"cp '{path}' '{evidence_dir}/malware/' 2>/dev/null")
        malware_found += 1

    result.stat("malware_files_preserved", malware_found)
    ok(f"Preserved {malware_found} malware file(s)")

    # ── 3. Server logs ─────────────────────────────────────────────────
    section("3. Collect server logs")
    log_sources = [
        ("/var/log/apache2/access.log",   "access.log"),
        ("/var/log/apache2/error.log",    "apache-error.log"),
        ("/var/log/nginx/access.log",     "nginx-access.log"),
        ("/var/log/php_errors.log",       "php-errors.log"),
        (wp.wp("wp-content/debug.log"),   "wp-debug.log"),
    ]
    for src, dst in log_sources:
        exists = wp.ssh(f"test -f '{src}' && echo Y || echo N")
        if exists == "Y":
            wp.ssh(f"cp '{src}' '{evidence_dir}/logs/{dst}' 2>/dev/null")
            ok(f"Collected: {dst}")

    # ── 4. WP Config (redacted) ────────────────────────────────────────
    section("4. wp-config.php (redacted)")
    wpconfig = wp.sftp_read(wp.wp("wp-config.php")).decode("utf-8", "replace")
    # Redact DB password
    import re
    redacted = re.sub(
        r"(define\s*\(\s*['\"]DB_PASSWORD['\"]\s*,\s*)['\"]([^'\"]+)['\"]",
        r"\1'***REDACTED***'",
        wpconfig
    )
    wp.sftp_write(f"{evidence_dir}/config/wp-config-redacted.txt", redacted.encode())
    ok("wp-config.php collected (password redacted)")

    # ── 5. .htaccess ──────────────────────────────────────────────────
    htaccess = wp.sftp_read(wp.wp(".htaccess"))
    wp.sftp_write(f"{evidence_dir}/config/htaccess.txt", htaccess)
    ok(".htaccess collected")

    # ── 6. Crontab ────────────────────────────────────────────────────
    section("5. Crontab & processes")
    crontab = wp.ssh("crontab -l 2>/dev/null || echo '(empty)'")
    wp.sftp_write(f"{evidence_dir}/config/crontab.txt", crontab.encode())
    ok("Crontab collected")

    # Running processes
    procs = wp.ssh("ps auxf 2>/dev/null | head -100")
    wp.sftp_write(f"{evidence_dir}/config/processes.txt", procs.encode())

    # Bash history
    hist = wp.ssh("cat ~/.bash_history 2>/dev/null | tail -200")
    if hist:
        wp.sftp_write(f"{evidence_dir}/config/bash-history.txt", hist.encode())
        ok("Bash history collected")

    # ── 7. DB dump (critical tables) ───────────────────────────────────
    section("6. Database dump (critical tables)")
    p = wp.db_prefix
    if all([wp.db_host, wp.db_user, wp.db_pass, wp.db_name]):
        tables = [
            f"{p}users", f"{p}usermeta", f"{p}options",
            f"{p}posts", f"{p}postmeta",
        ]
        for table in tables:
            dump = wp.ssh(
                f"mysqldump -h '{wp.db_host}' -u '{wp.db_user}' "
                f"-p'{wp.db_pass}' '{wp.db_name}' '{table}' 2>/dev/null | gzip",
                timeout=120
            )
            # mysqldump binary — save via file
            wp.ssh(
                f"mysqldump -h '{wp.db_host}' -u '{wp.db_user}' "
                f"-p'{wp.db_pass}' '{wp.db_name}' '{table}' 2>/dev/null "
                f"> '{evidence_dir}/db/{table}.sql'"
            )
            ok(f"Dumped: {table}")

    # ── 8. Session tokens (attacker IPs) ──────────────────────────────
    section("7. WP session tokens (attacker IP evidence)")
    if wp.db_host:
        sessions = wp.db(
            f"SELECT u.user_login, u.user_email, m.meta_value "
            f"FROM {p}users u "
            f"JOIN {p}usermeta m ON u.ID=m.user_id "
            f"WHERE m.meta_key='session_tokens';"
        )
        wp.sftp_write(
            f"{evidence_dir}/db/session-tokens-raw.txt",
            sessions.encode()
        )
        ok("Session tokens exported (contains attacker IPs)")

    # ── 9. Create archive ──────────────────────────────────────────────
    section("8. Create evidence archive")
    archive = wp.ssh(
        f"tar -czf '{archive_path}' -C /tmp 'wp-evidence-{ts}/' "
        f"&& echo OK || echo FAIL"
    )
    if "OK" in archive:
        size = wp.ssh(f"stat -c '%s' '{archive_path}' 2>/dev/null")
        ok(f"Evidence archive: {archive_path} ({size} bytes)")
        result.stat("archive_path_on_server", archive_path)
        result.stat("archive_size_bytes", size)
    else:
        err("Archive creation failed")

    # ── 10. Optional: download to local ───────────────────────────────
    if args.output_local and "OK" in archive:
        section("9. Download evidence archive to local")
        os.makedirs(args.output_local, exist_ok=True)
        local_path = os.path.join(args.output_local, f"wp-evidence-{ts}.tar.gz")
        sftp = wp._get_sftp()
        try:
            sftp.get(archive_path, local_path)
            local_size = os.path.getsize(local_path)
            ok(f"Downloaded to: {local_path} ({local_size} bytes)")
            result.stat("local_archive", local_path)
        except Exception as exc:
            err(f"Download failed: {exc}")

    # Cleanup temp dir (archive is kept)
    wp.ssh(f"rm -rf '{evidence_dir}'")

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WP-Arsenal: Collect forensic evidence from compromised WordPress",
    )
    add_connection_args(parser)
    parser.add_argument("--output-local", dest="output_local", default="",
                        help="Local directory to download evidence archive (optional)")
    args = parser.parse_args()

    print_banner("WP-FORENSICS — Evidence Collection", args.dry_run)

    if args.dry_run:
        warn("DRY-RUN: Forensics script previews only (no files collected)")
        sys.exit(0)

    with WPConnection(args) as wp:
        result = collect_evidence(wp, args)

    result.print_summary()

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()
