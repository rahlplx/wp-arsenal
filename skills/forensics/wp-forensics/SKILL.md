---
name: wp-forensics
description: >
  Collect forensic evidence from any compromised WordPress site. Preserves
  malware files, server logs, wp-config (redacted), crontab, processes, DB
  dumps of critical tables, and session tokens. Creates timestamped tar.gz.
  Always run before cleanup. Works on any host with SSH access.
metadata:
  type: forensics
  script: scripts/forensics/wp-forensics.py
  requires: paramiko
---

# WP-FORENSICS — Evidence Collection

**Run BEFORE any cleanup.** Evidence collected here is needed for police,
hosting provider abuse reports, and insurance claims.

## Usage

```bash
python scripts/forensics/wp-forensics.py \
  --config config/config.yaml \
  --output-local ./evidence/

# Or with flags:
python scripts/forensics/wp-forensics.py \
  --host ssh.host.com --user USER --password PASS \
  --wp-path /var/www/html/site \
  --db-host localhost --db-user USER --db-pass PASS --db-name DBNAME \
  --db-prefix wp_ --output-local ./evidence/
```

## What's collected

| Category | Content |
|----------|---------|
| Malware files | All PHP matching 14 signature patterns |
| Server logs | access.log, error.log, php_errors.log, debug.log |
| WP config | wp-config.php with DB password **redacted** |
| Server state | crontab, process list, bash history |
| Database | SQL dumps: users, usermeta, options, posts, postmeta |
| Session tokens | Contains attacker IP addresses if no VPN used |

## Output

Creates `/tmp/wp-evidence-YYYYMMDD-HHMMSS.tar.gz` on the server.
Pass `--output-local ./evidence/` to download it via SFTP.

## For police / abuse reports

The session_tokens dump contains real login IP addresses. If the attacker
logged into WP Admin without a VPN, their home IP is in this file.

Run `wp-attacker-profile` to extract and annotate those IPs automatically.

## Reporting resources

- **UK**: Action Fraud `actionfraud.police.uk` + NCSC `report.ncsc.gov.uk`
- **USA**: IC3 `ic3.gov` + CISA `cisa.gov/report`
- **EU**: ENISA `enisa.europa.eu/topics/incident-response`
- **Hosting abuse**: Find your host's `abuse@` address via `whois <host-IP>`
