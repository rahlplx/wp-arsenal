---
name: wp-firewall
description: >
  WordPress IP/geo firewall via .htaccess for any Apache-based host. Block
  attacker IPs, protect wp-login.php with an allowlist, geo-block countries
  via Cloudflare CF-IPCountry or mod_geoip. Config-driven, never blocks
  your trusted CIDRs. Not needed on Nginx/WP Engine/Kinsta (use their WAF).
metadata:
  type: security
  script: scripts/hardening/wp-firewall.py
  requires: paramiko
---

# WP-FIREWALL — IP/Geo Access Control

Works on any Apache-based host (shared hosting, cPanel, IONOS, SiteGround,
Bluehost, DreamHost, etc.). For Nginx hosts (WP Engine, Kinsta), use their
built-in IP block feature or Cloudflare WAF instead.

## Usage

```bash
# Block attacker IPs (--trusted-cidrs prevents accidental self-block)
python scripts/hardening/wp-firewall.py \
  --config config/config.yaml \
  --block-ip "1.2.3.4,5.6.7.0/24"

# Restrict wp-login.php to your IP only
python scripts/hardening/wp-firewall.py \
  --config config/config.yaml \
  --allow-admin-ip "YOUR_HOME_IP,YOUR_OFFICE_IP"

# Geo-block countries (Cloudflare or mod_geoip required)
python scripts/hardening/wp-firewall.py \
  --config config/config.yaml \
  --block-country "CN,RU,KP"

# Show what rules are currently active
python scripts/hardening/wp-firewall.py --config config/config.yaml --show

# Remove all WP-Arsenal rules from .htaccess
python scripts/hardening/wp-firewall.py --config config/config.yaml --clear
```

## Trusted CIDRs — always configure these

In `config/config.yaml`, list your hosting provider's monitoring IPs and your
own IPs under `trusted_cidrs`. The script refuses to block any trusted CIDR.

```yaml
trusted_cidrs:
  - "127.0.0.1"
  - "::1"
  - "82.165."      # IONOS monitoring (if on IONOS)
  - "203.0.113."   # Your office IP range
```

## How it works

Rules use `# WP-Arsenal-FW-BEGIN:LABEL` / `# WP-Arsenal-FW-END:LABEL` markers,
so re-running updates the block cleanly instead of appending duplicates.

## Geo-block prerequisites

- **Cloudflare** (free plan OK): automatically sends `CF-IPCountry` header
- **mod_geoip** on Apache: install with `apt-get install libapache2-mod-geoip`
- **No CDN, no mod_geoip**: country blocking won't work — use Cloudflare
