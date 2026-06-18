# WP-Arsenal — Claude Code Instructions

> Host-agnostic WordPress AI Agent Skills Repository.
> Security · Management · Restoration · Theme Design · Forensics

## What this repo is

A reusable toolkit of Python scripts, PHP MU-plugins, Claude skills, agent
definitions, and personas for managing, securing, and recovering WordPress
sites via SSH — on **any hosting provider, any WordPress version**.

## Quick start

```bash
bash install.sh                                  # install dependencies
cp config/config.example.yaml config/config.yaml # create your site config
# fill in SSH + DB credentials in config/config.yaml
python scripts/security/wp-scan.py --config config/config.yaml
```

## Architecture

```
wp-arsenal/
├── config/
│   ├── config.example.yaml          ← copy → config.yaml, fill in credentials
│   ├── isp-map.example.yaml         ← copy → isp-map.yaml, add attacker ISPs
│   └── sites/                       ← one config.yaml per site (multi-site)
├── scripts/
│   ├── wp_connect.py                ← shared SSH/SFTP/MySQL/HTTP library
│   ├── config_loader.py             ← YAML config → argparse merger
│   ├── security/                    ← wp-scan, wp-deep-audit, wp-chmod-fix, wp-shell-nuke, wp-theme-audit,
│   │                                   wp-woo-audit
│   ├── restoration/                 ← wp-restore-core, wp-plugin-restore, wp-elementor-fix
│   ├── management/                  ← wp-backup, wp-update, wp-user-audit, wp-multisite, wp-network-audit,
│   │                                   wp-report, wp-digest, wp-child-theme, wp-theme-switch
│   ├── cicd/                        ← wp-ci-deploy.py — backup → deploy → health-check → auto-rollback
│   ├── hardening/
│   │   ├── wp-harden.py
│   │   ├── wp-firewall.py
│   │   └── mu-plugins/              ← deploy to wp-content/mu-plugins/
│   │       ├── wp-arsenal-config.php.example  ← COPY + FILL IN per site
│   │       ├── mail-kill.php         ← suppress all WP mail (cleanup mode)
│   │       ├── login-monitor.php     ← alert on admin login from unknown IP
│   │       ├── honeypot.php          ← trap + WebRTC/canvas fingerprinting
│   │       ├── ip-blocker.php        ← PHP-level IP block (known-bad IPs)
│   │       ├── file-monitor.php      ← hourly file-change detection + alert
│   │       ├── rate-limiter.php      ← login brute-force lockout via transients
│   │       ├── xmlrpc-kill.php       ← disable XML-RPC + pingbacks at PHP level
│   │       ├── admin-guard.php       ← restrict wp-admin to trusted IPs only
│   │       └── security-headers.php  ← HSTS, CSP, X-Frame, Referrer-Policy
│   └── forensics/                   ← wp-forensics, wp-db-audit, wp-attacker-profile
├── skills/{security,management,forensics,theme-design,cicd}/*/SKILL.md
│   ├── theme-design/                ← kadence, elementor — design system + recovery guides
│   ├── cicd/                        ← wp-ci-deploy — pipeline integration guide
│   └── mine-patterns/              ← auto-pattern mining from proven OSS repos (extract → OKF → apply → feedback)
├── .github/workflows-examples/      ← copy into YOUR repo: scheduled scan + safe deploy templates
├── agents/*.md                      ← incident-responder, security-auditor, restoration, maintenance
├── personas/*.md                    ← security-analyst, wordpress-expert, theme-designer, site-manager
└── memory/site-credentials.md      ← gitignored — your actual credentials
```

## Configuration approach

Every script supports two input modes:

```bash
# Mode 1 — config file (recommended for regular use)
python scripts/security/wp-scan.py --config config/config.yaml

# Mode 2 — explicit CLI flags (for one-off use or CI/CD)
python scripts/security/wp-scan.py \
  --host ssh.host.com --user USER --password PASS \
  --wp-path /var/www/html/site
```

Config file values are always overridden by explicit CLI flags.

## Standard CLI flags (all scripts accept these)

| Flag | Description |
|------|-------------|
| `--config FILE` | Path to config.yaml (auto-detected if omitted) |
| `--host` | SSH hostname |
| `--user` | SSH username |
| `--password` | SSH password |
| `--wp-path` | Absolute path to WP root on server |
| `--db-host/user/pass/name/prefix` | MySQL connection details |
| `--site-url` | Public URL for HTTP probes |
| `--dry-run` | Preview changes without executing |
| `--json` | Machine-readable JSON output |
| `--trusted-cidrs` | Comma-separated IP prefixes to never alert/block |
| `--blocked-cidrs` | Comma-separated IP prefixes to block |

## Core library

All scripts import `wp_connect.py`:
```python
from wp_connect import WPConnection, add_connection_args, ok, err, section
with WPConnection(args) as wp:
    output = wp.ssh("ls /var/www/html")
    wp.sftp_write("/remote/path.php", content_bytes)
    rows   = wp.db("SELECT * FROM wp_options LIMIT 5")
    code   = wp.http_code("https://yoursite.com")
```

### SQL Security Helpers

New static methods on `WPConnection` for safe SQL literals and slug validation:

```python
# Safe single-quoted string interpolation
safe_value = WPConnection.sql_escape(user_input)
wp.db(f"SELECT * FROM {prefix}users WHERE login='{safe_value}';")

# Strict slug/identifier validation (theme names, usernames, etc.)
slug = WPConnection.sql_slug(user_input)  # Raises ValueError if invalid
wp.db(f"SELECT * FROM {prefix}options WHERE option_name='{slug}';")
```

- `sql_escape()`: Escapes backslash + single quote for safe interpolation inside single-quoted SQL literals
- `sql_slug()`: Validates slug format `[A-Za-z0-9_.-]`, rejects anything else (spaces, quotes, path traversal, SQL metacharacters)

Both helpers are tested by a comprehensive test suite (see Testing section below).

## Testing

Run the test suite before committing:
```bash
pip install pytest pytest-mock
pytest tests/ -v
```

Test coverage:
- **Unit tests** (`test_wp_connect.py`): 18 tests for `sql_escape()` and `sql_slug()` security helpers
  - SQL injection prevention, escaping edge cases, slug validation
- **Smoke tests** (`test_scripts_smoke.py`): 19 tests for script imports + mocked SSH integration
  - Catches regressions like the `wp-backup.py` `_ssh_client` AttributeError bug
  - Verifies all scripts import without errors
  - Tests core `WPConnection` operations with mocked paramiko (no real server needed)

**Test results:** 24 passed, 13 skipped (import tests for subdirectories)

All security-critical code paths are covered. See `tests/README.md` for full documentation.

## MU-Plugin deployment

```bash
# 1. Configure
cp scripts/hardening/mu-plugins/wp-arsenal-config.php.example \
   /your/wp/wp-content/mu-plugins/wp-arsenal-config.php
# Edit wp-arsenal-config.php — set alert email, trusted CIDRs, honeypot secret

# 2. Deploy (activate automatically — no WP Admin needed)
cp scripts/hardening/mu-plugins/honeypot.php      /your/wp/wp-content/mu-plugins/
cp scripts/hardening/mu-plugins/login-monitor.php  /your/wp/wp-content/mu-plugins/
cp scripts/hardening/mu-plugins/ip-blocker.php     /your/wp/wp-content/mu-plugins/
# mail-kill.php for cleanup-mode mail suppression
# rate-limiter.php for brute-force protection (recommended)
# xmlrpc-kill.php to disable XML-RPC (unless using Jetpack)
# admin-guard.php to restrict wp-admin to trusted IPs
# security-headers.php for HTTP security headers (recommended)
```

## Safety rules (always enforced)

1. **`--dry-run` first** on all destructive scripts (shell-nuke, harden, etc.)
2. **Forensics before cleanup** — run `wp-forensics` before `wp-shell-nuke`
3. **Configure `trusted_cidrs`** — prevents accidental self-block in firewall
4. **Never commit credentials** — `config.yaml` and `memory/site-credentials.md` are gitignored

## Supported hosts

Works on any host with SSH access and Apache or Nginx:
IONOS · SiteGround · Bluehost · DreamHost · HostGator · GoDaddy ·
Namecheap · A2 Hosting · WP Engine · Kinsta · Flywheel · Cloudways ·
DigitalOcean · Linode / Akamai · AWS Lightsail · VPS bare metal · cPanel / Plesk

## Skill discovery

Skills auto-load when Claude reads this CLAUDE.md.
Full skill details in `skills/*/SKILL.md`.
Agent plans in `agents/*.md`. Personas in `personas/*.md`.

## Auto-pattern mining (skills/mine-patterns/)

Mines proven patterns from curated OSS repos → OKF format → dry-run suggestions → human review.
Pipeline: `extract.py` (Python/PHP/YAML) → `okf.py` (format) → `apply.py` (suggest) → `feedback.py` (track).
Curated repos: fabric, bandit, click, yara, clamav, ModSecurity, PHP_CodeSniffer, phpstan, pytest, paramiko.
Run: `python skills/mine-patterns/extract.py <repo_path>` or use the skill in Claude Code.
