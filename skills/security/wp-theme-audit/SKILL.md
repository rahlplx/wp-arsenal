---
name: wp-theme-audit
description: >
  Security audit of WordPress themes via SSH. Scans for PHP malware patterns,
  injected scripts, recently modified files, and unexpected file types.
  Also checks DB for customizer injections and Elementor postmeta payloads.
  Use after any attack or before going live with a new/inherited theme.
triggers:
  - theme audit
  - check theme for malware
  - theme security
  - theme injection
  - scan theme files
  - theme modified
---

# Skill: wp-theme-audit

Scans the active theme (or any specified theme) for security issues —
from obfuscated PHP backdoors to injected scripts in the database.

## Usage

```bash
# Audit the active theme
python scripts/security/wp-theme-audit.py --config config/config.yaml

# Audit all installed themes
python scripts/security/wp-theme-audit.py --config config/config.yaml --all-themes

# Audit a specific theme
python scripts/security/wp-theme-audit.py --config config/config.yaml --theme twentytwentyfour

# Flag files modified in last 30 days (default: 14)
python scripts/security/wp-theme-audit.py --config config/config.yaml --days 30

# JSON output for report generation
python scripts/security/wp-theme-audit.py --config config/config.yaml --json > logs/theme-audit.json
```

## What is checked

### PHP file scanning (malware signatures)
| Pattern | Severity | Meaning |
|---------|----------|---------|
| `eval(base64_decode(...))` | CRITICAL | Classic PHP shell obfuscation |
| `eval(gzinflate(...))` | CRITICAL | Compressed backdoor payload |
| `preg_replace('/e', ...)` | CRITICAL | Code execution via regex |
| `create_function()` | HIGH | Deprecated function used by malware |
| `assert($_POST[...])` | CRITICAL | RCE via user input |
| `system()`, `exec()`, `passthru()` | HIGH | OS command execution |
| `file_get_contents('http...')` | HIGH | External file inclusion |
| Hardcoded external `<script>` | HIGH | Script injection |

### File integrity checks
- PHP files modified within last N days (configurable)
- Files with unexpected extensions (`.exe`, `.sh`, `.zip`, etc.)

### Database checks
- `theme_mods_*` options containing `<script>` or `eval(`
- Elementor `_elementor_data` postmeta containing injected scripts

## When to run

- On any inherited or purchased theme before first use
- After a malware incident (themes are a common persistence vector)
- As part of quarterly security audits
- Before deploying a site to production

## In the theme design workflow

```
wp-theme-audit → wp-child-theme → customise → wp-theme-audit again
↑ before touching anything     ↑ customise safely in child theme
```

## Common attack patterns in themes

**Backdoor in `functions.php`**: Attacker adds `eval(base64_decode(...))` at the
top of functions.php — survives plugin cleanup and WP core restore.

**Injected `<script>` in header.php**: External tracking/crypto-mining script
added to the theme's header template.

**Fake image with PHP content**: Attacker uploads `.jpg` file containing PHP
code, then uses a webshell to `include()` it. Look for PHP in uploads too.

**Customizer injection**: Script injected via the Customizer API
(`Additional CSS` or custom header/footer fields).
