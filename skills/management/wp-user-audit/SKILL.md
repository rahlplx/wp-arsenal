---
name: wp-user-audit
description: >
  WordPress user and role security audit via SSH + MySQL.
  Detects rogue admins, suspicious usernames, disposable emails, and active sessions.
  Can delete users, demote roles, and kill all sessions.
triggers:
  - user audit
  - check admin accounts
  - rogue admin
  - delete user
  - change user role
  - kill sessions
  - who is logged in
  - suspicious accounts
---

# Skill: wp-user-audit

Audits all WordPress user accounts for security issues and can perform
corrective actions (delete, demote, session kill) in the same tool.

## Audit mode (no changes)

```bash
# Full user audit
python scripts/management/wp-user-audit.py --config config/config.yaml

# Flag users created after breach date
python scripts/management/wp-user-audit.py --config config/config.yaml --since 2026-01-01

# JSON output
python scripts/management/wp-user-audit.py --config config/config.yaml --json
```

## What is checked

| Check | What triggers an alert |
|-------|----------------------|
| Admin count | More than 2 admins |
| Username patterns | Known attacker toolkit names (`archive_feed`, `wp_system_admin`, etc.) |
| Email domains | Disposable/throwaway email services |
| New users | Accounts created after `--since` date with admin role |
| Active sessions | Who is currently logged in and from which IP |

## Corrective actions

```bash
# Delete a rogue user (always dry-run first)
python scripts/management/wp-user-audit.py --config config/config.yaml \
    --delete-user rogue_admin --dry-run

python scripts/management/wp-user-audit.py --config config/config.yaml \
    --delete-user rogue_admin

# Demote admin to subscriber
python scripts/management/wp-user-audit.py --config config/config.yaml \
    --demote-user suspicious_account --role subscriber

# Kill all active sessions (forces re-login everywhere)
python scripts/management/wp-user-audit.py --config config/config.yaml \
    --kill-sessions all

# Kill sessions for specific user
python scripts/management/wp-user-audit.py --config config/config.yaml \
    --kill-sessions attacker_login
```

## In incident response

```
wp-forensics → wp-db-audit → wp-user-audit → wp-shell-nuke → ...
                              ↑ audit users, kill sessions, delete rogue accounts
```

## After an attack

1. Run `--kill-sessions all` immediately to eject attacker
2. Run audit to find rogue accounts (`--since BREACH_DATE`)
3. Delete confirmed rogue users
4. Change legitimate admin passwords via WP Admin

## Known attacker username patterns

The script flags usernames matching these patterns as HIGH severity:
- `archive_feed` — classic WPOC backdoor account
- `wp_system_admin` — commonly planted by automated exploits
- `admlnlx`, `admini` variants — character-substitution obfuscation
- `wordpress_admin[digits]` — mass-exploitation bots
- `admin[4+ digits]` — automated account creation
