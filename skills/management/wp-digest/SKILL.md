---
name: wp-digest
description: >
  Send a weekly multi-site security digest email aggregating all scan results.
  Reads JSON logs from wp-multisite sweeps, groups findings by site, and emails
  a colour-coded HTML digest with one-click attention flags. Use for agency
  weekly reporting or personal multi-site monitoring.
triggers:
  - weekly digest
  - send report email
  - multi-site report
  - email summary
  - weekly security email
  - digest email
---

# Skill: wp-digest

Aggregates all WP-Arsenal JSON logs from a directory into a weekly digest
email — one HTML email covering all your sites, with colour-coded severity
counts and a clear "needs attention" flag per site.

## Typical weekly workflow

```bash
# Monday 3am — sweep all sites and save JSON logs
python scripts/management/wp-multisite.py \
    --script wp-scan \
    --output-dir logs/weekly/

# Monday 4am — send digest email
python scripts/management/wp-digest.py \
    --logs-dir logs/weekly/ \
    --config config/config.yaml   # reads alerts.email and smtp.* section
```

## Usage

```bash
# Print digest to terminal (test mode — no email sent)
python scripts/management/wp-digest.py --logs-dir logs/weekly/ --print-only

# Send via SMTP
python scripts/management/wp-digest.py \
    --logs-dir logs/weekly/ \
    --to you@example.com \
    --smtp-host mail.yourdomain.com \
    --smtp-user you@example.com \
    --smtp-password "YourAppPassword"

# Send via config file (cleaner — credentials in config.yaml)
python scripts/management/wp-digest.py \
    --logs-dir logs/weekly/ \
    --config config/config.yaml

# Only show CRITICAL and HIGH findings (less noise)
python scripts/management/wp-digest.py \
    --logs-dir logs/weekly/ \
    --min-severity HIGH \
    --print-only

# Last 24 hours only (for daily digest)
python scripts/management/wp-digest.py \
    --logs-dir logs/ \
    --hours 24 \
    --config config/config.yaml
```

## Config file setup (config.yaml)

```yaml
alerts:
  email: "you@example.com"    # digest recipient

smtp:
  host: "mail.yourdomain.com"
  port: 587
  user: "alerts@yourdomain.com"
  password: "your-smtp-password"
  from_addr: "WP-Arsenal <alerts@yourdomain.com>"
```

## Gmail / Google Workspace

Use an **App Password** (not your account password):
- Google Account → Security → 2FA enabled → App Passwords → Mail → Generate
- `smtp-host: smtp.gmail.com`, `smtp-port: 587`

## Automating with cron

```bash
# crontab — weekly sweep Monday 3am, digest Monday 4am
0 3 * * 1 python3 /path/to/wp-multisite.py --script wp-scan --output-dir /var/log/wp-arsenal/weekly/
0 4 * * 1 python3 /path/to/wp-digest.py --logs-dir /var/log/wp-arsenal/weekly/ --config /path/to/config/config.yaml
```

## What the email looks like

```
WP-Arsenal Weekly Security Digest
Period: 2026-06-09 to 2026-06-16 | 5 sites | Min severity: LOW

⚠️ Sites needing attention: client-site3

[client-site1]  ✅ Clean
[client-site2]  ✅ Clean
[client-site3]  🔴 CRITICAL: 1  🟠 HIGH: 2    ← wp-scan found backdoor
[client-site4]  🟡 MEDIUM: 3
[client-site5]  ✅ Clean
```

Each site expands to show the script, category, and detail of each finding.
