---
name: wp-shell-nuke
description: >
  Remove WordPress malware and shell files. Deletes known-bad filenames, PHP from
  uploads, rogue plugin directories, and /tmp staging files. Always run --dry-run
  first. Blocks PHP execution in uploads via .htaccess.
metadata:
  type: security
  script: scripts/security/wp-shell-nuke.py
  requires: paramiko
---

# WP-SHELL-NUKE — Remove Malware Files

Deletes confirmed malware. **Always --dry-run first.**

## Usage

```bash
# Preview first
python scripts/security/wp-shell-nuke.py \
  --host HOST --user USER --password PASS --wp-path PATH --dry-run

# Execute
python scripts/security/wp-shell-nuke.py \
  --host HOST --user USER --password PASS --wp-path PATH
```

## What it removes

- Known attacker filenames: `offline.php`, `functions-interpreter.php`,
  `cache-handler.php`, `sso.php`, `site-compat.php`, `http-insights.php`,
  `filemanager.php`, `adminer.php`, `wso.php`, `c99.php`, `r57.php` etc.
- PHP files in `wp-content/uploads/`
- Rogue plugin directories: `fileorganizer`, `cacheengine`, `wp-file-manager`
- PHP files in `/tmp`

## What it also does

- Writes PHP-blocking `.htaccess` to uploads/ (even if no PHP found)

## Safety

- Never deletes WP core files
- Never deletes legitimate plugins unless explicitly in the rogue list
- `--dry-run` shows exactly what would be deleted before anything happens

## After running

Always run `wp-elementor-fix` and `wp-chmod-fix` afterwards to restore
correct permissions and CSS regeneration.
