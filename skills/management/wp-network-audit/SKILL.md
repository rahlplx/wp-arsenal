---
name: wp-network-audit
description: >
  Security audit for WordPress Multisite Network installations.
  Lists all sub-sites, detects super-admins, checks network-activated plugins
  vs filesystem, flags spam/deleted sites, reviews registration settings,
  and checks dangerous upload filetypes at the network level.
triggers:
  - multisite audit
  - network audit
  - WordPress network
  - WordPress multisite
  - sub-sites
  - super admin
  - network plugins
---

# Skill: wp-network-audit

Full security audit for WordPress Multisite (Network) installations. Covers
network-level configuration, sub-site inventory, and cross-site plugin integrity.

## Usage

```bash
# Full network audit
python scripts/management/wp-network-audit.py --config config/config.yaml

# Just list all sub-sites (fast)
python scripts/management/wp-network-audit.py --config config/config.yaml --list-sites

# Audit a specific sub-site by blog_id
python scripts/management/wp-network-audit.py --config config/config.yaml --site-id 3

# JSON output for reporting
python scripts/management/wp-network-audit.py --config config/config.yaml --json \
    > logs/network-audit.json
```

## What is audited

| Domain | Checks |
|--------|--------|
| Network detection | Is `MULTISITE` set in wp-config.php? |
| Registration | `none` / `user` / `blog` / `all` — open registration = risk |
| Super-admins | Count and list all network super-admins |
| Network plugins | Active network-wide plugins vs. filesystem (missing = fatal) |
| Sub-sites | Count, spam/deleted/archived flags |
| Per-site plugins | Each site's active plugins vs. filesystem |
| `siteurl` consistency | DB domain matches options siteurl? |
| Upload filetypes | Network-allowed file extensions (PHP/EXE = CRITICAL) |
| Illegal names | Reserved sub-site paths configured? |

## WordPress Network architecture

```
wp_               ← Main site tables (blog_id = 1)
wp_2_             ← Sub-site 2 tables
wp_3_             ← Sub-site 3 tables
wp_blogs          ← All sub-sites inventory
wp_sitemeta       ← Network-wide settings
wp_site           ← Network definition
```

- **Network-activated plugins** run on all sub-sites — missing from filesystem = all sites break
- **Super-admins** can manage all sub-sites and network settings
- **Registration = "all"** lets anyone create a new sub-site — major attack surface

## Detecting if a site is a network

```bash
grep -E "MULTISITE|SUBDOMAIN_INSTALL|DOMAIN_CURRENT_SITE" /path/to/wp-config.php
```

If `define('MULTISITE', true)` is present → this is a network install.

## Common network attack vectors

| Vector | Check in audit |
|--------|---------------|
| Rogue super-admin added | Super-admin list section |
| Network plugin deleted (breaks all sites) | Network plugin filesystem check |
| Public registration enabled → spam sub-sites | Registration setting check |
| PHP uploads allowed network-wide | Upload filetypes check |
| Sub-site siteurl redirected to attacker domain | Per-site siteurl check |

## In incident response (network)

```
wp-forensics → wp-network-audit → wp-deep-audit → wp-shell-nuke
               ↑ run early — establishes blast radius across all sub-sites
```

After cleanup: run `wp-network-audit --list-sites` to verify all sub-sites
are healthy before declaring the incident resolved.
