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
│   ├── security/                    ← wp-scan, wp-deep-audit, wp-chmod-fix, wp-shell-nuke
│   ├── restoration/                 ← wp-restore-core, wp-plugin-restore, wp-elementor-fix
│   ├── management/                  ← wp-backup, wp-update, wp-user-audit, wp-multisite, wp-network-audit
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
├── skills/{security,management,forensics}/*/SKILL.md
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
