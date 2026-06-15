---
name: wp-multisite
description: >
  Run any WP-Arsenal script across all sites in config/sites/.
  Produces a pass/fail summary table per site. Use for weekly security sweeps,
  mass updates, or post-incident lateral movement checks across multiple sites.
triggers:
  - multisite sweep
  - scan all sites
  - update all sites
  - backup all sites
  - run across all sites
  - agency sweep
---

# Skill: wp-multisite

Runs any WP-Arsenal script against every site in `config/sites/*.yaml` in
sequence, then produces a colour-coded summary table.

## Setup

Create one YAML config per managed site:

```bash
cp config/config.example.yaml config/sites/client-site1.yaml
cp config/config.example.yaml config/sites/client-site2.yaml
# fill in credentials for each
```

## Usage

```bash
# Weekly security scan across all sites
python scripts/management/wp-multisite.py --script wp-scan

# Check for updates across all sites (no changes)
python scripts/management/wp-multisite.py --script wp-update --args "--check-only"

# Back up all sites
python scripts/management/wp-multisite.py --script wp-backup --args "--keep 4"

# Deep audit all sites, save logs
python scripts/management/wp-multisite.py --script wp-deep-audit --output-dir logs/

# Harden all sites (dry-run first)
python scripts/management/wp-multisite.py --script wp-harden --args "--dry-run"
python scripts/management/wp-multisite.py --script wp-harden

# Run against specific sites only
python scripts/management/wp-multisite.py \
    --sites config/sites/site1.yaml,config/sites/site2.yaml \
    --script wp-scan

# Stop if any site fails
python scripts/management/wp-multisite.py --script wp-scan --stop-on-fail
```

## Available scripts

| Script name | Purpose |
|-------------|---------|
| `wp-scan` | Fast malware triage |
| `wp-deep-audit` | Full 8-domain audit |
| `wp-shell-nuke` | Remove malware |
| `wp-chmod-fix` | Fix permissions |
| `wp-harden` | Apply hardening |
| `wp-firewall` | Manage IP/geo rules |
| `wp-backup` | Create backup |
| `wp-update` | Update core/plugins |
| `wp-user-audit` | User security audit |
| `wp-forensics` | Evidence collection |
| `wp-db-audit` | Database audit |
| `wp-attacker-profile` | Attacker IP profiling |
| `wp-restore-core` | Restore WP core |
| `wp-elementor-fix` | Fix Elementor |
| `wp-plugin-restore` | Restore plugins |

## Weekly agency cron

```bash
# crontab — scan all sites every Monday 3am
0 3 * * 1 /usr/bin/python3 /path/to/wp-multisite.py \
    --script wp-scan \
    --output-dir /var/log/wp-arsenal/weekly/ \
    >> /var/log/wp-arsenal/multisite.log 2>&1
```

## Output

```
SWEEP RESULTS — wp-scan
────────────────────────────────────────────────────────
  PASS  client-site1
  PASS  client-site2
  FAIL  client-site3  → logs/20260616-030012-wp-scan-client-site3.json
────────────────────────────────────────────────────────
  Total: 3  Passed: 2  Failed: 1
```

Exit 0 = all sites passed. Exit 1 = one or more failed.
