# WP-Arsenal ⚔️

> **The WordPress AI Agent Skills Repository** — Security · Forensics · Restoration · Hardening · Management  
> Host-agnostic. Works on any WordPress site, any hosting provider.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-green.svg)](https://python.org)
[![Works on: IONOS · SiteGround · WP Engine · Kinsta · Bluehost · Any cPanel](https://img.shields.io/badge/host-any-orange.svg)](#supported-hosts)

---

## What is WP-Arsenal?

WP-Arsenal is a **reusable, agent-ready toolkit** for managing and securing WordPress sites via SSH. It gives AI agents (Claude, GPT, etc.), DevOps engineers, and WordPress professionals a structured library of:

- **Python scripts** — SSH-based tools for security scanning, malware removal, site restoration, and forensics
- **PHP MU-plugins** — always-on WordPress defences deployed directly to `wp-content/mu-plugins/`
- **Claude Skills** — structured SKILL.md files that Claude Code auto-discovers for guided workflows
- **Agent plans** — multi-step incident response and audit orchestration guides
- **Personas** — role-specific knowledge for security analysts, WordPress experts, and theme designers

Everything is **configuration-driven** — fill in one YAML file and all scripts and plugins use it. No hardcoded credentials, no vendor lock-in.

---

## Use Cases

### 🔒 Security Auditing
Run a fast 60-second malware triage or a full 8-domain forensic-quality audit on any WordPress site. Catches shells, backdoors, obfuscated code, injected scripts, and mis-configurations.

```bash
# Fast scan (< 60 seconds)
python scripts/security/wp-scan.py --config config/config.yaml

# Full 8-domain audit (3–8 minutes)
python scripts/security/wp-deep-audit.py --config config/config.yaml
```

### 🦠 Malware Removal
Identify and delete known malware files, remove PHP from uploads, wipe rogue plugin directories, and block PHP execution — all with a `--dry-run` preview.

```bash
python scripts/security/wp-shell-nuke.py --config config/config.yaml --dry-run
python scripts/security/wp-shell-nuke.py --config config/config.yaml
```

### 🔎 Forensics & Evidence Collection
Preserve forensic evidence **before** any cleanup. Collects malware samples, server logs, DB dumps of critical tables, and session tokens (which contain attacker IPs). Creates a timestamped archive suitable for police and ISP abuse reports.

```bash
python scripts/forensics/wp-forensics.py --config config/config.yaml --output-local ./evidence/
python scripts/forensics/wp-attacker-profile.py --config config/config.yaml --whois
```

### 🚒 Site Restoration
Restore a broken or attacked WordPress site from scratch: clean WP core, deleted plugins, Elementor CSS rendering, and file permissions — all scriptable.

```bash
python scripts/restoration/wp-restore-core.py    --config config/config.yaml
python scripts/restoration/wp-plugin-restore.py  --config config/config.yaml --plugins elementor,woocommerce --activate
python scripts/restoration/wp-elementor-fix.py   --config config/config.yaml
python scripts/security/wp-chmod-fix.py          --config config/config.yaml
```

### 🛡️ Hardening
Apply a security checklist to any WordPress site: `DISALLOW_FILE_EDIT`, xmlrpc lockdown, file browsing disabled, PHP execution blocked in uploads, wp-cron locked to server-only, pingbacks disabled.

```bash
python scripts/hardening/wp-harden.py  --config config/config.yaml --dry-run
python scripts/hardening/wp-harden.py  --config config/config.yaml
```

### 🧱 IP/Geo Firewall
Block attacker IP ranges, geo-block countries, and restrict `wp-login.php` to known IPs — all via `.htaccess`. Works with Cloudflare (CF-IPCountry header) or Apache mod_geoip.

```bash
python scripts/hardening/wp-firewall.py --config config/config.yaml --block-ip "1.2.3.4,5.6.7.0/24"
python scripts/hardening/wp-firewall.py --config config/config.yaml --allow-admin-ip "YOUR_HOME_IP"
python scripts/hardening/wp-firewall.py --config config/config.yaml --block-country "CN,RU,KP"
```

### 📊 Database Security Audit
Audit the WordPress database for injected scripts, rogue admin accounts, plugin–filesystem mismatches, Rank Math redirect abuse, and WP-cron tampering.

```bash
python scripts/forensics/wp-db-audit.py --config config/config.yaml
```

### 🎨 Theme & Elementor Recovery
Fix broken Elementor layouts after attacks or migrations — a common scenario where plugins are deleted but still listed as active in the database.

```bash
python scripts/restoration/wp-elementor-fix.py --config config/config.yaml
```

### 🤖 AI Agent Workflows
WP-Arsenal ships with Claude-compatible SKILL.md files and agent orchestration guides. When Claude Code reads `CLAUDE.md`, it auto-discovers all skills and can execute multi-step workflows like full incident response (`wp-incident-responder`) or scheduled multi-site audits (`wp-security-auditor`).

---

## Quick Start

### Prerequisites

- Python 3.9+
- SSH access to your WordPress hosting (any provider)
- WordPress database credentials (from `wp-config.php`)

### Install

```bash
git clone https://github.com/rahlplx/wp-arsenal.git
cd wp-arsenal
bash install.sh
```

`install.sh` installs `paramiko` (SSH) and `pyyaml` (config files), creates `config/config.yaml` from the template, and makes all scripts executable.

### Configure

```bash
# Edit your site credentials
nano config/config.yaml
```

Minimum required fields:

```yaml
ssh:
  host: "ssh.yourhostingprovider.com"
  user: "yourusername"
  password: "YourSSHPassword"

wordpress:
  path: "/var/www/html/yoursite"
  site_url: "https://yoursite.com"

alerts:
  email: "you@example.com"
```

### Run your first scan

```bash
python scripts/security/wp-scan.py --config config/config.yaml
```

---

## Project Structure

```
wp-arsenal/
│
├── config/
│   ├── config.example.yaml          ← copy → config.yaml (gitignored)
│   ├── isp-map.example.yaml         ← copy → isp-map.yaml for attacker IP labelling
│   └── sites/                       ← one config per site for multi-site setups
│
├── scripts/
│   ├── wp_connect.py                ← shared SSH/SFTP/MySQL/HTTP library
│   ├── config_loader.py             ← YAML config loader (merges with CLI args)
│   │
│   ├── security/
│   │   ├── wp-scan.py               ← fast 60s malware triage
│   │   ├── wp-deep-audit.py         ← 8-domain forensic audit
│   │   ├── wp-shell-nuke.py         ← delete confirmed malware
│   │   ├── wp-chmod-fix.py          ← fix file/directory permissions
│   │   └── signatures.txt           ← malware signature database
│   │
│   ├── restoration/
│   │   ├── wp-restore-core.py       ← restore clean WordPress core
│   │   ├── wp-plugin-restore.py     ← restore deleted plugins
│   │   └── wp-elementor-fix.py      ← fix Elementor CSS rendering
│   │
│   ├── hardening/
│   │   ├── wp-harden.py             ← security constants + .htaccess rules
│   │   ├── wp-firewall.py           ← IP/geo block via .htaccess
│   │   └── mu-plugins/
│   │       ├── wp-arsenal-config.php.example  ← template for MU-plugin config
│   │       ├── mail-kill.php         ← suppress all WP email (cleanup mode)
│   │       ├── login-monitor.php     ← alert on admin login from unknown IP
│   │       ├── honeypot.php          ← trap + JS fingerprinting (WebRTC real IP)
│   │       └── ip-blocker.php        ← PHP-level IP block
│   │
│   └── forensics/
│       ├── wp-forensics.py          ← full evidence collection + archive
│       ├── wp-db-audit.py           ← database security audit
│       └── wp-attacker-profile.py   ← extract attacker IPs for police reports
│
├── skills/
│   ├── security/                    ← wp-scan, wp-deep-audit, wp-harden, wp-firewall, wp-shell-nuke
│   ├── management/                  ← wp-plugin-restore, wp-elementor-fix
│   └── forensics/                   ← wp-forensics, wp-attacker-profile
│
├── agents/
│   ├── wp-incident-responder.md     ← full breach response orchestration
│   ├── wp-security-auditor.md       ← scheduled multi-site auditing
│   └── wp-restoration-agent.md      ← site restoration diagnosis + fix
│
├── personas/
│   ├── security-analyst.md          ← forensics + legal framework knowledge
│   ├── wordpress-expert.md          ← WP internals + hosting provider quirks
│   └── theme-designer.md            ← Kadence/Elementor UI recovery
│
├── memory/
│   └── site-credentials.md          ← your credentials (gitignored — template only)
│
├── CLAUDE.md                        ← Claude Code auto-discovery + usage guide
├── install.sh                       ← dependency installer + config setup
└── README.md                        ← this file
```

---

## Configuration Reference

### config/config.yaml

All scripts accept `--config path/to/config.yaml`. If omitted, the script auto-detects `config/config.yaml` from the repo root.

```yaml
ssh:
  host: "ssh.yourhostingprovider.com"   # SSH hostname
  user: "yourusername"
  password: "YourSSHPassword"
  port: 22                               # default

wordpress:
  path: "/var/www/html/yoursite"        # absolute path to WP root on server
  site_url: "https://yoursite.com"

database:
  host: "localhost"                      # check wp-config.php DB_HOST
  user: "dbuser"
  password: "dbpassword"
  name: "dbname"
  prefix: "wp_"                          # check wp-config.php $table_prefix

alerts:
  email: "you@example.com"
  bcc: ""                                # optional second address

trusted_cidrs:
  - "127.0.0.1"
  - "::1"
  # Add your hosting provider's monitoring IPs here
  # Add your own office/home IP ranges here

blocked_cidrs: []
  # Populate from wp-attacker-profile output

hosting:
  provider: "ionos"                      # ionos | siteground | wpengine | kinsta | bluehost | etc.
  # When set, provider-specific monitoring CIDRs are auto-trusted

sibling_sites:
  []
  # Other WP installs on the same server — used by wp-plugin-restore for instant copy
```

### CLI flags (override config.yaml)

Every script accepts these flags. CLI values always override config file:

```
--host          SSH hostname
--user          SSH username  
--password      SSH password
--port          SSH port (default: 22)
--wp-path       Absolute WP root path on server
--db-host       MySQL hostname
--db-user       MySQL username
--db-pass       MySQL password
--db-name       MySQL database name
--db-prefix     WP table prefix (default: wp_)
--site-url      Public URL for HTTP probes
--alert-email   Where security alerts go
--trusted-cidrs Comma-separated IP prefixes to never block
--blocked-cidrs Comma-separated IP prefixes to block
--dry-run       Preview changes without executing
--json          Machine-readable JSON output
--quiet         Suppress progress output
```

### Finding your credentials

```bash
# SSH into your server, then:

# 1. Find your WP root path
find / -name "wp-config.php" 2>/dev/null | grep -v node_modules | head -5

# 2. Get DB credentials from wp-config.php
grep -E "DB_(NAME|USER|PASSWORD|HOST)|table_prefix" /path/to/wp-config.php
```

---

## MU-Plugin Deployment

MU-plugins activate automatically — no WP Admin required. Deploy once, always active.

```bash
# 1. Configure (fill in alert email, trusted IPs, honeypot secret)
cp scripts/hardening/mu-plugins/wp-arsenal-config.php.example \
   /path/to/wp-content/mu-plugins/wp-arsenal-config.php

# 2. Deploy the plugins you want
cp scripts/hardening/mu-plugins/login-monitor.php  /path/to/wp-content/mu-plugins/
cp scripts/hardening/mu-plugins/honeypot.php        /path/to/wp-content/mu-plugins/
cp scripts/hardening/mu-plugins/ip-blocker.php      /path/to/wp-content/mu-plugins/

# For emergency mail suppression during cleanup:
cp scripts/hardening/mu-plugins/mail-kill.php       /path/to/wp-content/mu-plugins/
# (and set WP_ARSENAL_MAIL_KILL = true in wp-arsenal-config.php)
```

### What each MU-plugin does

| Plugin | Purpose | Configures via |
|--------|---------|----------------|
| `wp-arsenal-config.php` | Central config (required by all others) | Edit directly |
| `login-monitor.php` | Email alert on admin login from unknown IP | `WP_ARSENAL_ALERT_EMAIL`, `WP_ARSENAL_TRUSTED_CIDRS` |
| `honeypot.php` | Hidden trap + WebRTC/canvas fingerprinting | `WP_ARSENAL_HONEYPOT_SECRET` |
| `ip-blocker.php` | PHP-level IP block before WP loads | `WP_ARSENAL_BLOCKED_CIDRS` |
| `mail-kill.php` | Suppress all outbound WP email | `WP_ARSENAL_MAIL_KILL = true` |

---

## Script Reference

### Security

| Script | What it does | Time |
|--------|-------------|------|
| `wp-scan.py` | Fast malware triage — 8 check categories | < 60s |
| `wp-deep-audit.py` | Full 8-domain security audit | 3–8 min |
| `wp-shell-nuke.py` | Delete known malware files, block PHP in uploads | 1–2 min |
| `wp-chmod-fix.py` | Fix world-writable files, set dirs 755 / files 644 | 1–2 min |

### Restoration

| Script | What it does | Time |
|--------|-------------|------|
| `wp-restore-core.py` | Download + rsync clean WP core (skips wp-content) | 2–5 min |
| `wp-plugin-restore.py` | Restore deleted plugins from sibling site or wp.org | 1–10 min |
| `wp-elementor-fix.py` | Fix Elementor CSS rendering (bump cache version, clear meta) | < 1 min |

### Hardening

| Script | What it does |
|--------|-------------|
| `wp-harden.py` | Add security constants to wp-config, .htaccess rules |
| `wp-firewall.py` | Block IPs, restrict wp-login.php, geo-block countries |

### Forensics

| Script | What it does | Time |
|--------|-------------|------|
| `wp-forensics.py` | Collect all evidence → timestamped tar.gz | 2–5 min |
| `wp-db-audit.py` | DB audit: users, injections, options, cron abuse | 1–3 min |
| `wp-attacker-profile.py` | Extract attacker IPs from session tokens + logs | 1–2 min |

---

## Incident Response Workflow

When a site is compromised, run scripts in this order:

```
1. TRIAGE      →  wp-scan           (what's wrong?)
2. EVIDENCE    →  wp-forensics       (preserve before cleanup)
3. PROFILE     →  wp-attacker-profile (who did it?)
4. AUDIT       →  wp-deep-audit      (full damage assessment)
5. CLEAN       →  wp-shell-nuke      (remove malware)
6. DB AUDIT    →  wp-db-audit        (check for DB injections)
7. RESTORE     →  wp-restore-core + wp-plugin-restore + wp-elementor-fix
8. PERMISSIONS →  wp-chmod-fix
9. HARDEN      →  wp-harden + wp-firewall
10. VERIFY     →  wp-scan            (confirm clean)
```

> Always run `wp-forensics` before `wp-shell-nuke`. Evidence deleted = evidence lost.

---

## Multi-Site Usage

For agencies or anyone managing multiple WordPress sites:

```bash
# One config file per site
cp config/config.example.yaml config/sites/site1.com.yaml
cp config/config.example.yaml config/sites/site2.com.yaml
# fill in each one

# Sweep all sites
for cfg in config/sites/*.yaml; do
    echo "=== $(grep site_url $cfg | head -1) ==="
    python scripts/security/wp-scan.py --config "$cfg" --json \
        >> logs/weekly-scan.json
done
```

---

## AI Agent Integration

WP-Arsenal is designed to be used with AI coding assistants (Claude Code, etc.).

### Claude Code (auto-discovery)

When you open this repo in Claude Code, it reads `CLAUDE.md` and automatically discovers all skills. Ask Claude:

- *"Scan this WordPress site for malware"* → loads `wp-scan` skill
- *"The site is broken after a hack — restore it"* → loads `wp-incident-responder` agent
- *"Collect forensic evidence before cleanup"* → loads `wp-forensics` skill
- *"Fix Elementor not rendering"* → loads `wp-elementor-fix` skill

### Skills available

| Skill | Trigger phrase |
|-------|----------------|
| `wp-scan` | "scan", "check for malware", "quick audit" |
| `wp-deep-audit` | "full audit", "deep scan", "security report" |
| `wp-shell-nuke` | "remove malware", "delete shells", "nuke backdoors" |
| `wp-harden` | "harden", "secure", "apply security" |
| `wp-firewall` | "block IP", "firewall", "geo-block" |
| `wp-plugin-restore` | "restore plugins", "plugins missing" |
| `wp-elementor-fix` | "elementor broken", "site shows text", "fix layout" |
| `wp-forensics` | "collect evidence", "forensics", "evidence archive" |
| `wp-attacker-profile` | "who attacked", "attacker IP", "profile hacker" |

---

## Supported Hosts

Works on any host with SSH access. Tested configurations:

| Provider | Apache | Nginx | .htaccess | Notes |
|----------|--------|-------|-----------|-------|
| IONOS | ✅ | — | ✅ | Set `hosting.provider: ionos` in config |
| SiteGround | ✅ | — | ✅ | Set `hosting.provider: siteground` |
| Bluehost | ✅ | — | ✅ | MySQL on localhost |
| HostGator | ✅ | — | ✅ | cPanel-based |
| DreamHost | ✅ | — | ✅ | |
| GoDaddy | ✅ | — | ✅ | |
| A2 Hosting | ✅ | — | ✅ | |
| Namecheap | ✅ | — | ✅ | |
| WP Engine | — | ✅ | ❌ | Use their IP block UI for firewall rules |
| Kinsta | — | ✅ | ❌ | Use MyKinsta or Cloudflare for IP blocks |
| Flywheel | — | ✅ | ❌ | |
| Cloudways | ✅/✅ | ✅ | ✅ | Depends on stack |
| DigitalOcean | ✅/✅ | ✅ | ✅ | VPS — full control |
| AWS Lightsail | ✅/✅ | ✅ | ✅ | VPS — full control |
| Linode / Akamai | ✅/✅ | ✅ | ✅ | VPS — full control |
| Any cPanel host | ✅ | — | ✅ | |
| Any Plesk host | ✅ | ✅ | ✅ | |
| Bare Linux VPS | ✅/✅ | ✅ | ✅ | |

> **Nginx hosts (WP Engine, Kinsta)**: `.htaccess` rules don't apply. Use those platforms' built-in IP block features or Cloudflare WAF for firewall rules. All other scripts (scan, audit, restore, forensics) work fully.

---

## Security & Privacy

- **Credentials are never committed** — `config/config.yaml`, `config/isp-map.yaml`, and `memory/site-credentials.md` are all gitignored
- **Passwords only in memory** — scripts receive credentials via CLI args or config file; nothing is stored in git
- **`--dry-run` on all destructive scripts** — always preview before executing
- **Forensics first** — the incident response workflow preserves evidence before any deletion
- **No hacking back** — this toolkit is strictly defensive; no offensive capabilities

---

## Requirements

```
Python 3.9+
paramiko      (SSH connections)
pyyaml        (config file support — optional, can use CLI flags instead)
```

Install: `pip install paramiko pyyaml`  
Or: `bash install.sh` (handles everything)

---

## Contributing

Pull requests welcome. Focus areas:

- Additional malware signature patterns (`scripts/security/signatures.txt`)
- Support for new hosting provider quirks
- Additional restoration scenarios
- New SKILL.md files for Claude Code
- Additional MU-plugins for WordPress hardening

---

## License

MIT — use freely, modify freely, no warranty.

---

## Acknowledgements

Built from real-world WordPress incident response experience. The malware signatures, restoration procedures, and agent workflows were developed while responding to actual attacks on production WordPress sites.

---

*WP-Arsenal — Because WordPress security shouldn't require starting from scratch every time.*
