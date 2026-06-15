---
name: wp-db-audit
description: >
  WordPress database security audit via SSH + MySQL.
  Detects injected scripts, rogue admin users, plugin-filesystem mismatches,
  Rank Math redirect abuse, WP-cron tampering, and rogue option rows.
  Use early in incident response before any cleanup.
triggers:
  - database audit
  - db audit
  - check database
  - injected scripts
  - database injection
  - rogue options
  - WP cron tampering
---

# Skill: wp-db-audit

Full database-layer security audit. Checks all 7 domains of the WordPress
database for attacker footprints without touching the filesystem.

## Audit domains

| Domain | What is checked |
|--------|----------------|
| Users | All accounts, capabilities, unknown admins |
| active_plugins | DB entries vs. filesystem — flags missing plugin files |
| Critical options | `siteurl`, `home`, `blogdescription`, `admin_email` |
| Post/postmeta injection | `<script>`, `eval(`, `base64_decode` in content |
| Rank Math redirects | Suspicious redirect rules (attacker-planted) |
| WP-Cron | Scheduled hook names matching malware patterns |
| Rogue option rows | Known plugin prefixes: `ihaf_%`, `fileorganizer%`, `cacheengine%` |
| Session tokens | Current logins with source IPs |

## Usage

```bash
python scripts/forensics/wp-db-audit.py --config config/config.yaml

# JSON output for further processing
python scripts/forensics/wp-db-audit.py --config config/config.yaml --json > db-audit.json
```

## When to run

- First step of incident response (before touching any files)
- When `wp-scan.py` finds anomalies but you need database confirmation
- After restoring core/plugins — verify DB state is also clean
- Periodic audits (monthly/quarterly)

## In the incident response order

```
wp-forensics → wp-db-audit → wp-deep-audit → wp-shell-nuke → ...
               ↑ run here (read-only, safe to run first)
```

## Key findings and what they mean

**Missing plugins in active_plugins**: Plugin was deleted from filesystem
but still listed in DB → causes PHP fatal on page load. Fix with
`wp-plugin-restore.py`.

**Script injection in posts/postmeta**: Attacker injected JavaScript or PHP
via compromised admin account or XSS. Fix with:
```sql
UPDATE wp_posts SET post_content = REPLACE(post_content, '<script>...', '') WHERE ...
```

**Rank Math redirect abuse**: Attacker used Rank Math SEO's redirect manager
to add a redirect rule that sends visitors to a malware/spam site.

**Rogue WP-Cron hooks**: Malware registers a scheduled event to re-infect
the site after cleanup. Must be removed from the cron option.

## Output

Each finding includes severity (CRITICAL/HIGH/MEDIUM/LOW), category, and
detail. Exit 1 = critical or high findings present.
