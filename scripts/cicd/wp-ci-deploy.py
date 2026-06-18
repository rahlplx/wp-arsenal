#!/usr/bin/env python3
"""
wp-ci-deploy.py — CI/CD-safe WordPress deployment
====================================================
Deploys a local directory (theme, plugin, or wp-content subset) to a
WordPress server via SFTP, with a pre-deploy backup, a post-deploy HTTP
health check, and automatic rollback if the site breaks.

Designed to be called from a GitHub Actions / GitLab CI / Jenkins pipeline
on merge to main. Exits non-zero on failure so the pipeline fails loudly.

Usage:
  python wp-ci-deploy.py --config config/config.yaml \
      --local-path ./dist/my-theme \
      --remote-path wp-content/themes/my-theme

  python wp-ci-deploy.py --config config/config.yaml \
      --local-path ./dist/my-theme \
      --remote-path wp-content/themes/my-theme \
      --dry-run
"""

import argparse
import os
import sys
import tarfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wp_connect import (
    WPConnection, add_connection_args, connect_from_args, print_banner,
    ok, warn, err, info, section, RED, GREEN, YELLOW, BOLD
)

BACKUP_DIR_REL = "wp-content/wp-arsenal-ci-backups"


def make_remote_backup(wp: WPConnection, remote_path: str) -> str:
    """Tar the existing remote_path before overwriting it. Returns backup filename."""
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    backup_name = f"backup-{remote_path.replace('/', '_')}-{timestamp}.tar.gz"
    backup_dir = wp.wp(BACKUP_DIR_REL)
    full_remote = wp.wp(remote_path)

    wp.ssh(f"mkdir -p '{backup_dir}'")
    if wp.wp_exists(remote_path):
        wp.ssh(f"tar -czf '{backup_dir}/{backup_name}' -C '{wp.wp_path}' '{remote_path}' 2>/dev/null")
        ok(f"Pre-deploy backup created: {BACKUP_DIR_REL}/{backup_name}")
    else:
        info(f"{remote_path} does not exist yet on server — nothing to back up (fresh deploy)")
        backup_name = ""
    return backup_name


def restore_remote_backup(wp: WPConnection, remote_path: str, backup_name: str) -> None:
    if not backup_name:
        warn("No backup available to restore from — manual intervention required")
        return
    backup_dir = wp.wp(BACKUP_DIR_REL)
    full_remote = wp.wp(remote_path)
    wp.ssh(f"rm -rf '{full_remote}'")
    wp.ssh(f"tar -xzf '{backup_dir}/{backup_name}' -C '{wp.wp_path}'")
    ok(f"Rolled back {remote_path} from {backup_name}")


def upload_directory(wp: WPConnection, local_path: str, remote_path: str) -> int:
    """Upload a local directory tree to the server via SFTP. Returns file count."""
    full_remote = wp.wp(remote_path)
    sftp = wp._get_sftp()
    file_count = 0

    if wp.dry_run:
        for root, _, files in os.walk(local_path):
            file_count += len(files)
        info(f"[DRY-RUN] Would upload {file_count} file(s) to {remote_path}")
        return file_count

    wp.ssh(f"mkdir -p '{full_remote}'")
    for root, dirs, files in os.walk(local_path):
        rel_dir = os.path.relpath(root, local_path)
        remote_dir = full_remote if rel_dir == "." else f"{full_remote}/{rel_dir.replace(os.sep, '/')}"
        wp.ssh(f"mkdir -p '{remote_dir}'")
        for fname in files:
            local_file = os.path.join(root, fname)
            remote_file = f"{remote_dir}/{fname}"
            with open(local_file, "rb") as f:
                content = f.read()
            wp.sftp_write(remote_file, content)
            file_count += 1
    return file_count


def main():
    parser = argparse.ArgumentParser(description="CI/CD-safe WordPress deployment")
    add_connection_args(parser)
    parser.add_argument("--local-path", required=True, dest="local_path",
                         help="Local directory to deploy (relative to CI working dir)")
    parser.add_argument("--remote-path", required=True, dest="remote_path",
                         help="Destination path relative to WP root (e.g. wp-content/themes/my-theme)")
    parser.add_argument("--health-check-path", default="/", dest="health_check_path",
                         help="Path appended to --site-url for post-deploy health check (default: /)")
    parser.add_argument("--no-rollback", action="store_true",
                         help="Disable automatic rollback on failed health check")
    parser.add_argument("--keep-backups", type=int, default=10,
                         help="Number of CI backups to retain per target (default: 10)")
    args = parser.parse_args()

    print_banner("WP-ARSENAL — CI/CD Deploy", dry_run=args.dry_run)

    if not os.path.isdir(args.local_path):
        sys.exit(RED(f"Local path not found: {args.local_path}"))

    wp = connect_from_args(args)
    try:
        section("1. Pre-deploy backup")
        backup_name = make_remote_backup(wp, args.remote_path)

        section("2. Pre-deploy health check")
        if args.site_url:
            pre_code = wp.http_code(args.site_url.rstrip("/") + args.health_check_path)
            info(f"Site responded {pre_code} before deploy")
        else:
            warn("No --site-url configured — skipping pre-deploy health check")

        section("3. Upload")
        count = upload_directory(wp, args.local_path, args.remote_path)
        ok(f"Uploaded {count} file(s) to {args.remote_path}")

        section("4. Post-deploy health check")
        if args.dry_run:
            ok("[DRY-RUN] Skipping live health check")
        elif args.site_url:
            time.sleep(2)
            post_code = wp.http_code(args.site_url.rstrip("/") + args.health_check_path)
            if post_code.startswith("2") or post_code.startswith("3"):
                ok(f"Site responded {post_code} after deploy — deployment successful")
            else:
                err(f"Site responded {post_code} after deploy — treating as failed deployment")
                if not args.no_rollback:
                    section("5. Auto-rollback")
                    restore_remote_backup(wp, args.remote_path, backup_name)
                    sys.exit(RED("Deployment rolled back due to failed health check"))
                else:
                    sys.exit(RED("Deployment health check failed — rollback disabled, manual fix required"))
        else:
            warn("No --site-url configured — cannot verify deployment health automatically")

        section("6. Backup retention")
        if not args.dry_run:
            backup_dir = wp.wp(BACKUP_DIR_REL)
            prefix = f"backup-{args.remote_path.replace('/', '_')}-"
            listing = wp.ssh(f"ls -1t '{backup_dir}' 2>/dev/null | grep '^{prefix}'")
            files = [l for l in listing.splitlines() if l.strip()]
            for old in files[args.keep_backups:]:
                wp.ssh(f"rm -f '{backup_dir}/{old}'")
            if len(files) > args.keep_backups:
                ok(f"Pruned {len(files) - args.keep_backups} old backup(s), kept {args.keep_backups}")

        print(f"\n{GREEN(BOLD('DEPLOY SUCCESSFUL'))}\n")
    finally:
        wp.close()


if __name__ == "__main__":
    main()
