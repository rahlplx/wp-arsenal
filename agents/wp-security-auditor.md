---
name: wp-security-auditor
description: >
  Proactive WordPress security audit agent. Runs scheduled deep audits across
  multiple sites, tracks posture over time, reports findings with remediation
  steps. Fully host-agnostic. Configures per site via config/config.yaml.
role: Security Auditor
persona: security-analyst
---

# WP Security Auditor Agent

## Purpose

Regular scheduled auditing across any number of WordPress sites — not incident
response (use `wp-incident-responder` for that).

## Setup per site

1. Copy `config/config.example.yaml` → `config/sites/yoursite.yaml`
2. Fill in SSH, WordPress, and DB credentials
3. Set `alerts.email` to where you want alerts sent
4. Add hosting provider monitoring IPs to `trusted_cidrs`

## Audit cadence

| Frequency | Check | Script |
|-----------|-------|--------|
| Daily | HTTP reachability | `curl --head $SITE_URL` |
| Weekly | Fast malware scan | `wp-scan --config sites/yoursite.yaml` |
| Monthly | Full 8-domain audit | `wp-deep-audit --config sites/yoursite.yaml` |
| After plugin update | Permission check + fast scan | `wp-chmod-fix` + `wp-scan` |
| After breach | Full incident response | See `wp-incident-responder` |

## Multi-site sweep script

```bash
#!/usr/bin/env bash
# sweep.sh — run wp-scan across all configured sites
for cfg in config/sites/*.yaml; do
    site=$(grep "site_url" "$cfg" | awk '{print $2}')
    echo "=== Scanning $site ==="
    python scripts/security/wp-scan.py --config "$cfg" --json \
        >> logs/scan-$(date +%Y%m%d).json
done
```

## Reporting format

```
WEEKLY SCAN REPORT — 2026-01-15
================================
Sites audited:  4
Clean:          3
High findings:  1

FINDINGS:
- site2.com: PHP in uploads (wp-content/uploads/images.php) [CRITICAL]
  → Run: wp-shell-nuke --config config/sites/site2.yaml

RECOMMENDED:
- Update WordPress core on site3.com (6.4.1 → 6.5.3)
- Rotate SSH password on site4.com (>90 days old)
```

## Escalation rules

| Severity | Action |
|----------|--------|
| CRITICAL | Immediate alert email, begin incident response |
| HIGH | Alert email within 1 hour |
| MEDIUM | Include in weekly digest |
| LOW/INFO | Monthly summary only |
