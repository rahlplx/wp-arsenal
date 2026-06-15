---
name: wp-maintenance-agent
description: >
  Scheduled WordPress maintenance orchestration — weekly, monthly, and quarterly tasks.
  Covers backups, updates, permission checks, user audits, and performance checks.
  Designed for agencies and anyone managing multiple WordPress sites on a schedule.
---

# WP Maintenance Agent

Orchestrates regular WordPress maintenance tasks to keep sites healthy, updated,
secure, and recoverable. Run via `wp-multisite.py` for multi-site sweeps or
individually per site.

## Maintenance Schedule

### Weekly (every Monday, automated)

```bash
# 1. Backup all sites first
python scripts/management/wp-backup.py --config CONFIG --keep 8

# 2. Security scan
python scripts/security/wp-scan.py --config CONFIG --json > logs/weekly-scan.json

# 3. Check for available updates (report only)
python scripts/management/wp-update.py --config CONFIG --check-only
```

**Review**: Check scan output for any CRITICAL/HIGH findings. If found, escalate
to the incident response workflow (`wp-incident-responder` agent).

---

### Monthly (first Monday)

```bash
# 1. Backup
python scripts/management/wp-backup.py --config CONFIG --keep 12

# 2. Apply plugin updates
python scripts/management/wp-update.py --config CONFIG --all

# 3. User audit — look for new accounts
python scripts/management/wp-user-audit.py --config CONFIG --since LAST_MONTH

# 4. Database audit
python scripts/forensics/wp-db-audit.py --config CONFIG

# 5. Permission check
python scripts/security/wp-chmod-fix.py --config CONFIG

# 6. Verify site responds
python scripts/security/wp-scan.py --config CONFIG
```

**Review**: Check for new admin accounts, outdated plugins that aren't on
wordpress.org (premium), database anomalies.

---

### Quarterly

```bash
# 1. Full forensic audit
python scripts/security/wp-deep-audit.py --config CONFIG

# 2. Hardening review (dry-run shows gaps)
python scripts/hardening/wp-harden.py --config CONFIG --dry-run

# 3. Firewall review — are blocked IPs still relevant?
python scripts/hardening/wp-firewall.py --config CONFIG --list

# 4. Attacker profile check — any new honeypot hits?
python scripts/forensics/wp-attacker-profile.py --config CONFIG

# 5. SSL expiry check
curl -svo /dev/null https://SITE_URL 2>&1 | grep -E "expire|issuer"
```

**Review**: Update firewall rules, review any new honeypot activity, renew SSL
if within 30 days of expiry, check if any plugins have been abandoned on wp.org.

---

## Multi-Site Agency Schedule

```bash
# WEEKLY — scan all client sites
python scripts/management/wp-multisite.py --script wp-scan --output-dir logs/weekly/

# WEEKLY — backup all
python scripts/management/wp-multisite.py --script wp-backup --args "--keep 8"

# MONTHLY — update all
python scripts/management/wp-multisite.py --script wp-update --args "--all"

# MONTHLY — user audit all
python scripts/management/wp-multisite.py --script wp-user-audit --output-dir logs/monthly/

# QUARTERLY — deep audit all
python scripts/management/wp-multisite.py --script wp-deep-audit --output-dir logs/quarterly/
```

---

## Pre-Update Checklist

Before applying any major WordPress or plugin update:

```
□ Run wp-backup.py (always)
□ Note current WP version and plugin versions
□ Run wp-scan.py (confirm clean before updating)
□ Apply updates via wp-update.py
□ Verify site responds (HTTP 200)
□ Click through key pages manually
□ Run wp-scan.py again (confirm still clean)
```

---

## Post-Hack Recovery Handoff

If the site shows signs of compromise during a maintenance scan:

1. Stop maintenance — do not apply updates to a compromised site
2. Hand off to `wp-incident-responder` agent
3. After incident is resolved, re-run the monthly maintenance cycle
4. Document the incident in site notes

---

## Maintenance Log Template

```
Site: [site URL]
Date: [YYYY-MM-DD]
Performed by: [name/agent]

Tasks completed:
  □ Backup: [backup path / size]
  □ WP version: [before] → [after]
  □ Plugins updated: [list]
  □ Security scan: PASS / FAIL [findings if any]
  □ User audit: [admin count, any new accounts]
  □ DB audit: PASS / FAIL

Issues found: [none / description]
Follow-up needed: [none / description]
```
