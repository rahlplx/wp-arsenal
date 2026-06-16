---
name: wp-ci-deploy
description: >
  Deploy a theme, plugin, or wp-content subset to a WordPress server from a
  CI/CD pipeline, with automatic pre-deploy backup, post-deploy health check,
  and automatic rollback on failure. Designed for GitHub Actions, GitLab CI,
  or any pipeline that can run Python.
triggers:
  - CI/CD deploy
  - GitHub Actions deploy
  - automated deploy
  - deploy theme
  - deploy plugin
  - rollback deploy
---

# Skill: wp-ci-deploy

Deploys local build output to a live WordPress site safely from a pipeline.
Unlike a plain `rsync`/`scp` step, this script treats the deploy as
transactional: backup → upload → health check → rollback-if-broken.

## Usage

```bash
# Deploy a built theme directory
python scripts/cicd/wp-ci-deploy.py --config config/config.yaml \
    --local-path ./dist/my-theme \
    --remote-path wp-content/themes/my-theme

# Preview without making changes
python scripts/cicd/wp-ci-deploy.py --config config/config.yaml \
    --local-path ./dist/my-theme \
    --remote-path wp-content/themes/my-theme \
    --dry-run

# Custom health-check path (e.g. a specific page that must load)
python scripts/cicd/wp-ci-deploy.py --config config/config.yaml \
    --local-path ./dist/my-plugin \
    --remote-path wp-content/plugins/my-plugin \
    --health-check-path /shop/

# Disable auto-rollback (not recommended — manual fix required on failure)
python scripts/cicd/wp-ci-deploy.py --config config/config.yaml \
    --local-path ./dist/my-theme \
    --remote-path wp-content/themes/my-theme \
    --no-rollback
```

## What happens on deploy

1. **Backup**: tars the existing `--remote-path` (if it exists) into
   `wp-content/wp-arsenal-ci-backups/` on the server, timestamped
2. **Pre-deploy health check**: records the site's HTTP status before
   touching anything (informational baseline)
3. **Upload**: walks the local directory and writes every file via SFTP
4. **Post-deploy health check**: requests `--site-url` + `--health-check-path`
   — if the response isn't 2xx/3xx, the deploy is considered failed
5. **Auto-rollback** (unless `--no-rollback`): restores the pre-deploy backup
   and exits non-zero — the CI job fails loudly
6. **Backup retention**: prunes old backups, keeping the most recent
   `--keep-backups` (default 10) per target path

## CI/CD integration

Two ready-to-copy GitHub Actions templates are in
`.github/workflows-examples/`:

| Template | Purpose |
|----------|---------|
| `wp-security-scan.yml.example` | Scheduled daily scan (wp-scan + wp-theme-audit + wp-woo-audit) with digest email alert |
| `wp-deploy.yml.example` | Build + deploy a theme/plugin on push to main, with health-check rollback |

Copy the relevant `.example` file into **your own** repo's
`.github/workflows/` (drop the `.example` suffix), and add the required
secrets (`WP_SSH_HOST`, `WP_SSH_USER`, `WP_SSH_PASSWORD`, `WP_PATH`,
`WP_SITE_URL`, DB credentials, SMTP credentials as applicable) to that
repo's GitHub Secrets.

These templates are intentionally kept as `.example` files (not under
`.github/workflows/` in this repo) so they never accidentally execute
against the wp-arsenal repository itself — they're meant to run in the
repo that holds your actual site/theme code or your private ops config.

## Why not just `rsync` or `scp` directly in CI

- No backup — a bad deploy has no automatic undo
- No health check — a broken deploy ships silently until someone notices
- No retention policy — manual backups accumulate forever or get forgotten

`wp-ci-deploy.py` wraps all three in one step so a single pipeline failure
means the site was automatically restored, not left broken.

## Limitations

- Designed for theme/plugin directories, not full-site deploys (use
  `wp-backup.py` + manual restore, or a dedicated deploy tool, for
  database/full-site migrations)
- Health check only verifies HTTP status code — it cannot detect a
  visually broken page that still returns 200. Pair with a real
  smoke-test/E2E step in your pipeline for critical pages.
- Rollback restores files only — if the deploy included a DB migration
  (e.g. via a plugin activation hook), rollback does not undo DB changes.
  Run `wp-backup.py` separately before any deploy that touches the DB.
