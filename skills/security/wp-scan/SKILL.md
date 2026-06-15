---
name: wp-scan
description: >
  Fast WordPress malware scan for any site on any host. Detects known shell
  filenames, PHP in uploads, recently modified PHP, 14 malware signatures
  (eval/base64, c99, TFM/Nyx, assert, preg_replace/e), and .htaccess anomalies.
  Runs in under 60 seconds. Use as first triage on any suspect site.
metadata:
  type: security
  script: scripts/security/wp-scan.py
  requires: paramiko
---

# WP-SCAN — Fast Malware Surface Scan

First-pass triage for any WordPress site. Use `wp-deep-audit` for full analysis.

## Usage — with config file

```bash
cp config/config.example.yaml config/config.yaml
# fill in ssh + wordpress sections
python scripts/security/wp-scan.py --config config/config.yaml
```

## Usage — flags only

```bash
python scripts/security/wp-scan.py \
  --host ssh.yourhostingprovider.com \
  --user yourusername \
  --password "password" \
  --wp-path /var/www/html/yoursite
```

## What it checks

| Check | Detail |
|-------|--------|
| WP root files | Non-standard PHP files in WP root |
| Known bad names | 25+ known attacker filenames |
| PHP in uploads | Any .php file in wp-content/uploads/ |
| Recent changes | PHP files modified in last 14 days |
| Malware sigs | eval+base64, c99, WSO, assert(), preg_replace/e, etc. |
| .htaccess | Dangerous directives (AddHandler, auto_prepend, Indexes) |
| SSH keys | Unexpected authorized_keys entries |
| Hidden files | Dot-files in WP root |

## Exit codes

- `0` — no CRITICAL/HIGH findings
- `1` — CRITICAL or HIGH findings detected (use in CI or monitoring cron)

## Cron example (weekly automated scan)

```bash
# Run every Monday at 07:00, email results if findings
0 7 * * 1 python /path/to/wp-arsenal/scripts/security/wp-scan.py \
  --config /path/to/wp-arsenal/config/config.yaml --json \
  >> /var/log/wp-scan.json 2>&1
```
