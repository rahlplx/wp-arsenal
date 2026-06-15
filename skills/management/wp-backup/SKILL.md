---
name: wp-backup
description: >
  Full WordPress site backup via SSH — database dump + wp-content/ archive.
  Stores backup on server with rotation, optionally downloads locally.
  Use before any destructive operation or on a maintenance schedule.
triggers:
  - backup site
  - backup WordPress
  - create backup
  - export database
  - backup before update
---

# Skill: wp-backup

Creates a timestamped backup of a WordPress site: MySQL dump + wp-content/ archive
+ wp-config.php copy. Handles rotation and optional local download.

## What is backed up

| Component | File created |
|-----------|-------------|
| MySQL database | `wp-backup-YYYYMMDD-HHMMSS-db.sql.gz` |
| wp-content/ | `wp-backup-YYYYMMDD-HHMMSS-files.tar.gz` (cache excluded) |
| wp-config.php | `wp-backup-YYYYMMDD-HHMMSS-wp-config.php` |

Backup is stored in `../wp-arsenal-backups/` relative to the WP root by default.

## Usage

```bash
# Full backup (DB + files)
python scripts/management/wp-backup.py --config config/config.yaml

# Download backup to local machine
python scripts/management/wp-backup.py --config config/config.yaml --output-local ./backups/

# DB-only (faster, smaller)
python scripts/management/wp-backup.py --config config/config.yaml --no-files

# Files-only (no DB)
python scripts/management/wp-backup.py --config config/config.yaml --no-db

# Custom rotation (default is 7 sets)
python scripts/management/wp-backup.py --config config/config.yaml --keep 14

# Custom backup directory on server
python scripts/management/wp-backup.py --config config/config.yaml --backup-dir /backups/mysite
```

## When to run

- **Before any cleanup operation** (`wp-shell-nuke`, `wp-harden`, etc.)
- **Before WordPress updates** (`wp-update.py`)
- **Before plugin changes**
- On a weekly cron schedule for all managed sites

## Cron automation (weekly backup)

```bash
# Add to crontab or IONOS scheduled tasks:
0 2 * * 0 /usr/bin/python3 /path/to/wp-arsenal/scripts/management/wp-backup.py \
    --config /path/to/config/config.yaml \
    --keep 4 >> /var/log/wp-arsenal-backup.log 2>&1
```

## Restore from backup

```bash
# Restore database
gunzip < wp-backup-20260615-020000-db.sql.gz | mysql -u USER -pPASS DB_NAME

# Restore wp-content/
tar -xzf wp-backup-20260615-020000-files.tar.gz -C /path/to/wordpress/
```

## Before every destructive operation

```
wp-backup → wp-forensics → wp-shell-nuke → ...
↑ always first
```
