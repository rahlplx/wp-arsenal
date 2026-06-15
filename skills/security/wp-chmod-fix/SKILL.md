---
name: wp-chmod-fix
description: >
  Fix WordPress file and directory permissions via SSH.
  Sets directories to 755, PHP files to 644, wp-config.php to 600.
  Detects world-writable files and PHP files with execute bit set.
  Use after malware cleanup or server misconfiguration.
triggers:
  - fix permissions
  - chmod
  - world-writable
  - file permissions wrong
  - 777 files
---

# Skill: wp-chmod-fix

Fixes file and directory permissions on any WordPress installation via SSH.
Run this after malware cleanup, plugin restore, or any time permissions look wrong.

## What it fixes

| Target | Permission set |
|--------|---------------|
| Directories | `755` (owner rwx, group/other rx) |
| PHP files | `644` (owner rw, group/other r) |
| `wp-config.php` | `600` (owner rw only — most restrictive) |
| Non-PHP files | `644` |
| `.htaccess` | `644` |
| World-writable files | Flagged + fixed to `644` or `755` |
| PHP with execute bit | Flagged + execute bit removed |

## Usage

```bash
# Preview changes first
python scripts/security/wp-chmod-fix.py --config config/config.yaml --dry-run

# Apply fixes
python scripts/security/wp-chmod-fix.py --config config/config.yaml
```

## When to run

- After `wp-shell-nuke.py` (malware removal changes file states)
- After `wp-plugin-restore.py` (downloaded files may have wrong perms)
- After `wp-restore-core.py` (rsync'd files may inherit wrong perms)
- When `wp-scan.py` or `wp-deep-audit.py` reports world-writable files
- After any manual file upload via SFTP

## In the incident response workflow

```
wp-forensics → wp-shell-nuke → wp-restore-core → wp-plugin-restore → wp-chmod-fix → wp-harden
                                                                       ↑ run here
```

## Output

Reports each change: `dirs fixed`, `php files fixed`, `world-writable files found`, `execute-bit removed`.
Exit 0 = all permissions now correct. Exit 1 = errors encountered.
