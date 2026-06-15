---
name: wp-attacker-profile
description: >
  Build an attacker IP/identity profile from WordPress forensic data. Extracts
  IPs from session_tokens, honeypot logs, login monitor alerts. Cross-references
  with a configurable ISP map or runs whois automatically. Output suitable for
  police reports and ISP abuse complaints. Works on any WP install.
metadata:
  type: forensics
  script: scripts/forensics/wp-attacker-profile.py
  requires: paramiko
---

# WP-ATTACKER-PROFILE — Forensic IP Analysis

## Usage

```bash
# With ISP map (recommended — adds context to raw IPs)
python scripts/forensics/wp-attacker-profile.py \
  --config config/config.yaml \
  --isp-map config/isp-map.yaml \
  --json > attacker-profile.json

# With auto-whois (slower — queries whois for each IP on the server)
python scripts/forensics/wp-attacker-profile.py \
  --config config/config.yaml --whois

# Quick run (IPs only, no ISP lookup)
python scripts/forensics/wp-attacker-profile.py \
  --config config/config.yaml
```

## ISP map setup

```bash
cp config/isp-map.example.yaml config/isp-map.yaml
# Edit to add attacker ISP ranges — e.g.:
# "103.45.67.":  "FastHost ISP, City, Country"
```

## What it extracts

1. **WP session_tokens** — Login IPs stored per-user (bypasses VPN if attacker authenticated to WP Admin without one)
2. **Honeypot hits** — IP + WebRTC fingerprint from `honeypot.php` error_log
3. **Login monitor alerts** — Admin logins logged by `login-monitor.php`
4. **Suspicious admin accounts** — Pattern-matched against common attacker usernames

## How to use the output for abuse reports

1. Take each IP from the profile
2. Run `whois <IP>` to find the ISP's abuse contact
3. Email `abuse@<isp>` with: incident date/time, IP, damage description
4. Also report to national cybercrime agency (Action Fraud, IC3, etc.)

## ISP contact tips

Most ISPs respond to abuse reports within 24-72 hours. Include:
- Your site URL
- The exact IP address
- Date and time (UTC) of the incident
- A description of what was done (malware upload, admin account creation, etc.)
- Evidence (attach the attacker profile JSON)
