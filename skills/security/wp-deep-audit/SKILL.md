---
name: wp-deep-audit
description: >
  Comprehensive 8-domain WordPress security audit: filesystem, malware signatures,
  database, wp-config, plugins/themes, server/cron, network/DNS, and logs.
  Works on any host (IONOS, SiteGround, WP Engine, Kinsta, cPanel, etc.).
  Produces incident-quality report. Takes 3-8 minutes per site.
metadata:
  type: security
  script: scripts/security/wp-deep-audit.py
  requires: paramiko
---

# WP-DEEP-AUDIT — 8-Domain Security Audit

Full forensic-quality audit for any WordPress installation. Use `wp-scan` for
fast triage; use this for post-breach analysis or quarterly reviews.

## Usage — with config file (recommended)

```bash
# Create and fill in your config
cp config/config.example.yaml config/config.yaml
# edit config/config.yaml with your SSH + DB credentials

python scripts/security/wp-deep-audit.py --config config/config.yaml
```

## Usage — all flags (no config file)

```bash
python scripts/security/wp-deep-audit.py \
  --host ssh.yourhostingprovider.com \
  --user youruser \
  --password "YourSSHPassword" \
  --wp-path /var/www/html/yoursite \
  --db-host localhost \
  --db-user dbuser \
  --db-pass "dbpassword" \
  --db-name dbname \
  --db-prefix wp_ \
  --site-url https://yoursite.com
```

## Finding your SSH credentials

| Host | Where to find SSH details |
|------|--------------------------|
| IONOS | My IONOS → Hosting → SSH |
| SiteGround | Site Tools → Dev → SSH Keys |
| Bluehost | Hosting → SSH Access |
| Kinsta | MyKinsta → Sites → SSH/SFTP |
| WP Engine | User Portal → SSH Gateway |
| cPanel hosts | cPanel → Terminal or SSH Access |

## Finding your wp-path

SSH in and run: `find /var/www /home /public_html -name "wp-config.php" 2>/dev/null`

## Domains covered

| Domain | What's checked |
|--------|---------------|
| A | Hidden files, recently modified PHP, PHP in uploads, world-writable, SSH keys |
| B | 14 malware signature patterns (eval, base64, c99, TFM, assert, etc.) |
| C | Admin users, session IPs, critical options, DB injection |
| D | Security constants in wp-config, WP_DEBUG, auto_prepend_file |
| E | All installed plugins, obfuscated code, active theme integrity |
| F | Crontab, PHP processes, /tmp PHP staging |
| G | HTTP status, xmlrpc, SSL expiry |
| H | Access logs, login attempts |
