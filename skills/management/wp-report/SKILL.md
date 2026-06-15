---
name: wp-report
description: >
  Generate self-contained HTML or plain-text audit reports from WP-Arsenal JSON output.
  Combines results from multiple scripts into one colour-coded report.
  Use after any audit run to produce a shareable deliverable for clients or records.
triggers:
  - generate report
  - create report
  - HTML report
  - audit report
  - security report
  - export findings
---

# Skill: wp-report

Converts the JSON output from any WP-Arsenal script into a clean, self-contained
HTML report — one file, no internet required, safe to email or archive.

## Workflow

```bash
# Step 1 — run scripts with --json flag
python scripts/security/wp-scan.py       --config config/config.yaml --json > logs/scan.json
python scripts/security/wp-deep-audit.py --config config/config.yaml --json > logs/deep-audit.json
python scripts/forensics/wp-db-audit.py  --config config/config.yaml --json > logs/db-audit.json

# Step 2 — combine into one HTML report
python scripts/management/wp-report.py \
    --input logs/scan.json logs/deep-audit.json logs/db-audit.json \
    --output reports/site-audit-2026-06-16.html \
    --site-label "example.com — June 2026"
```

## Usage

```bash
# Single file → HTML report
python scripts/management/wp-report.py \
    --input logs/scan.json \
    --output reports/scan.html

# All JSON files in a directory → one combined report
python scripts/management/wp-report.py \
    --input-dir logs/weekly/ \
    --output reports/weekly-summary.html \
    --site-label "Weekly sweep — 2026-06-16"

# Plain text (for terminal, plain-text email, or log archiving)
python scripts/management/wp-report.py \
    --input logs/scan.json \
    --format text

# Print to stdout (no --output = stdout)
python scripts/management/wp-report.py \
    --input logs/deep-audit.json \
    --format text | mail -s "Site audit" client@example.com
```

## Report contents

- **Severity summary cards** (CRITICAL / HIGH / MEDIUM / LOW / INFO counts)
- **Per-script sections** — findings table with severity badge, category, detail, path
- **Stats table** — script-specific counters (files scanned, plugins checked, etc.)
- Self-contained HTML — works offline, safe to attach to emails

## Common patterns

### Full incident audit report
```bash
# Run all scripts
for script in wp-forensics wp-deep-audit wp-db-audit wp-attacker-profile; do
    python scripts/forensics/${script}.py --config config/config.yaml --json \
        > logs/${script}-$(date +%Y%m%d).json
done

# Generate report
python scripts/management/wp-report.py \
    --input-dir logs/ \
    --output reports/incident-report-$(date +%Y%m%d).html \
    --site-label "Incident Report — $(date +%Y-%m-%d)"
```

### Client-ready report after cleanup
```bash
python scripts/security/wp-scan.py --config config/config.yaml --json > logs/post-cleanup-scan.json
python scripts/management/wp-report.py \
    --input logs/post-cleanup-scan.json \
    --output "reports/Clean Bill of Health — $(date +%Y-%m-%d).html" \
    --site-label "Post-cleanup verification"
```
