# Anti-Pattern: World-Readable /tmp Archives

## Symptom
Evidence collected from a compromised server is stored in `/tmp/wp-evidence-<ts>/` and `/tmp/wp-evidence-<ts>.tar.gz` with default permissions (755/644 — world-readable). Any other local user on the shared server can read forensic evidence including database dumps, wp-config.php (with DB credentials), and malware files.

## Root Cause
`mkdir` and `tar` use process umask for default permissions. On shared hosting (which is the main use case for wp-arsenal), other users share the same server. A `755` directory and `644` archive are readable by all.

## Fix Applied
```bash
# Directory: restrict immediately after creation
mkdir -p '/tmp/wp-evidence-...' && chmod 700 '/tmp/wp-evidence-...'

# Archive: restrict immediately after creation
tar -czf '/tmp/wp-evidence-....tar.gz' ... && chmod 600 '/tmp/wp-evidence-....tar.gz'
```

The `&&` chains ensure chmod only runs on successful creation. chmod in same ssh() call eliminates the race window between mkdir and chmod.

## How vibe-stack Should Catch It
Pattern: any `mkdir /tmp/` without an immediately-following `chmod 7[0-9][0-9]` in the same command or next line. Harness: `grep -A2 "mkdir.*\/tmp\/" scripts/ | grep -v chmod`.

## Incident
wp-arsenal, wp-forensics.py, 2026-06-19. MEDIUM severity — exploitable on shared hosting where multiple users have shell access.
