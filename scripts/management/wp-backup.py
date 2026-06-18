#!/usr/bin/env python3
"""
wp-backup.py — Full WordPress site backup via SSH
==================================================
Creates a backup containing:
  - MySQL database dump (all tables)
  - wp-content/ archive (files, themes, plugins, uploads)
  - wp-config.php (DB password redacted in filename, kept in archive)

Backup is stored on the server and optionally downloaded locally.
Rotation keeps only the last N backups on the server.

Usage:
  python wp-backup.py --config config/config.yaml
  python wp-backup.py --config config/config.yaml --output-local ./backups/
  python wp-backup.py --config config/config.yaml --no-files       # DB only
  python wp-backup.py --config config/config.yaml --no-db          # files only
  python wp-backup.py --config config/config.yaml --keep 14        # keep 14 rotations
"""

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
from wp_connect import (
    WPConnection, add_connection_args, print_banner, AuditResult,
    ok, warn, err, info, section
)


def backup_database(wp: WPConnection, backup_dir: str, label: str) -> str | None:
    """Create MySQL dump, return remote path or None on failure."""
    dump_path = f"{backup_dir}/{label}-db.sql.gz"
    info(f"Dumping database to {dump_path}...")

    pass_escaped = wp.db_pass.replace("'", "'\\''")
    cmd = (
        f"MYSQL_PWD='{pass_escaped}' mysqldump"
        f" -h '{wp.db_host}'"
        f" -u '{wp.db_user}'"
        f" '{wp.db_name}'"
        f" 2>/dev/null"
        f" | gzip > '{dump_path}'"
        f" && echo OK || echo FAIL"
    )
    result = wp.ssh(cmd, timeout=300)
    if "FAIL" in result or "OK" not in result:
        err("Database dump failed")
        return None

    size = wp.ssh(f"du -sh '{dump_path}' 2>/dev/null | cut -f1")
    ok(f"Database dump: {dump_path} ({size.strip()})")
    return dump_path


def backup_files(wp: WPConnection, backup_dir: str, label: str) -> str | None:
    """Archive wp-content/, return remote path or None on failure."""
    archive_path = f"{backup_dir}/{label}-files.tar.gz"
    wp_content = wp.wp("wp-content")
    info(f"Archiving wp-content/ to {archive_path}...")

    # Exclude cache directories to keep archive small
    exclude_flags = (
        "--exclude='cache'"
        " --exclude='backups'"
        " --exclude='uploads/cache'"
        " --exclude='*.log'"
    )
    cmd = (
        f"tar -czf '{archive_path}' {exclude_flags}"
        f" -C '{wp.wp_path}' wp-content"
        f" 2>/dev/null && echo OK || echo FAIL"
    )
    result = wp.ssh(cmd, timeout=600)
    if "FAIL" in result or "OK" not in result:
        err("File archive failed")
        return None

    size = wp.ssh(f"du -sh '{archive_path}' 2>/dev/null | cut -f1")
    ok(f"File archive: {archive_path} ({size.strip()})")
    return archive_path


def backup_config(wp: WPConnection, backup_dir: str, label: str) -> str | None:
    """Copy wp-config.php into backup dir."""
    config_src = wp.wp("wp-config.php")
    config_dst = f"{backup_dir}/{label}-wp-config.php"
    result = wp.ssh(f"cp '{config_src}' '{config_dst}' && echo OK || echo FAIL")
    if "OK" in result:
        ok(f"wp-config.php backed up")
        return config_dst
    return None


def rotate_backups(wp: WPConnection, backup_dir: str, keep: int) -> None:
    """Delete oldest backups, keeping only `keep` sets."""
    # List all backup directories, sorted oldest first
    listing = wp.ssh(
        f"ls -1dt '{backup_dir}'/wp-backup-* 2>/dev/null | tail -n +{keep + 1}"
    )
    if not listing.strip():
        return
    for old in listing.strip().splitlines():
        old = old.strip()
        if old:
            wp.ssh(f"rm -rf '{old}' 2>/dev/null")
            info(f"Rotated old backup: {old}")


def download_backup(wp: WPConnection, remote_dir: str, local_dir: str, label: str) -> None:
    """Download all files from remote backup dir to local_dir."""
    os.makedirs(local_dir, exist_ok=True)
    files = wp.ssh(f"ls '{remote_dir}/' 2>/dev/null").strip().splitlines()
    for fname in files:
        fname = fname.strip()
        if not fname:
            continue
        remote_path = f"{remote_dir}/{fname}"
        local_path = os.path.join(local_dir, fname)
        info(f"Downloading {fname}...")
        try:
            sftp = wp._get_sftp()
            sftp.get(remote_path, local_path)
            size_bytes = os.path.getsize(local_path)
            ok(f"Downloaded {fname} ({size_bytes // 1024}KB) → {local_path}")
        except Exception as exc:
            err(f"Download failed for {fname}: {exc}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WP-Arsenal: Full WordPress site backup"
    )
    add_connection_args(parser)
    parser.add_argument("--output-local", dest="output_local", default="",
                        help="Local directory to download backup into (optional)")
    parser.add_argument("--backup-dir", dest="backup_dir", default="",
                        help="Server-side directory to store backups (default: WP_PATH/../backups)")
    parser.add_argument("--keep", type=int, default=7,
                        help="Number of backup sets to keep on server (default: 7)")
    parser.add_argument("--no-db", action="store_true",
                        help="Skip database dump")
    parser.add_argument("--no-files", action="store_true",
                        help="Skip file archive")
    args = parser.parse_args()

    label = time.strftime("wp-backup-%Y%m%d-%H%M%S")
    result = AuditResult("wp-backup")

    print_banner(f"WP-BACKUP — {label}", args.dry_run)

    with WPConnection(args) as wp:
        # Determine backup dir on server
        server_backup_dir = args.backup_dir
        if not server_backup_dir:
            parent = wp.wp_path.rstrip("/").rsplit("/", 1)[0]
            server_backup_dir = f"{parent}/wp-arsenal-backups"

        section("Setup")
        if not wp.dry_run:
            setup = wp.ssh(
                f"mkdir -p '{server_backup_dir}/{label}' && echo OK || echo FAIL"
            )
            if "FAIL" in setup:
                err(f"Cannot create backup dir: {server_backup_dir}")
                return
            ok(f"Backup dir: {server_backup_dir}/{label}")
        else:
            info(f"[DRY-RUN] Would create: {server_backup_dir}/{label}")

        this_backup = f"{server_backup_dir}/{label}"

        # Database backup
        if not args.no_db:
            section("Database backup")
            if wp.dry_run:
                info("[DRY-RUN] Would dump database")
            else:
                db_path = backup_database(wp, this_backup, label)
                if db_path:
                    result.add("INFO", "backup-db", f"DB dumped to {db_path}", db_path)
                else:
                    result.add("HIGH", "backup-db-failed", "Database dump failed", "")

        # Files backup
        if not args.no_files:
            section("Files backup")
            if wp.dry_run:
                info("[DRY-RUN] Would archive wp-content/")
            else:
                files_path = backup_files(wp, this_backup, label)
                if files_path:
                    result.add("INFO", "backup-files", f"Files archived to {files_path}", files_path)
                else:
                    result.add("HIGH", "backup-files-failed", "File archive failed", "")

                config_path = backup_config(wp, this_backup, label)
                if config_path:
                    result.add("INFO", "backup-config", "wp-config.php backed up", config_path)

        # Rotation
        if not wp.dry_run and args.keep > 0:
            section(f"Rotation (keep {args.keep})")
            rotate_backups(wp, server_backup_dir, args.keep)

        # Download
        if args.output_local and not wp.dry_run:
            section("Downloading backup locally")
            download_backup(wp, this_backup, args.output_local, label)
            ok(f"Backup downloaded to {args.output_local}")

        # Report backup size
        if not wp.dry_run:
            total_size = wp.ssh(f"du -sh '{this_backup}' 2>/dev/null | cut -f1")
            result.stat("backup_path", this_backup)
            result.stat("total_size", total_size.strip())

    result.print_summary()
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()
