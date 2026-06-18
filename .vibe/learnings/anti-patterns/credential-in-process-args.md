# Anti-Pattern: Credentials in Process Arguments

## Symptom
Database password visible in `ps auxf` output on the remote server during
mysqldump/mysql execution:
```
mysql  -h localhost -u wpuser -p'secret123' wpdb
```

## Root Cause
Using `-p'...'` CLI flag appends the credential to the process argv, which
is readable by all processes running as the same OS user via `/proc/*/cmdline`.

## How vibe-stack Should Catch It
Harness check: scan all `.ssh()` call strings in Python scripts for patterns like:
```
grep -rn "\-p'" scripts/  # flags -p'password' in ssh commands
```
Flag any `mysqldump` or `mysql` invocation that contains `-p` followed by a quote.

## Incident
wp-arsenal, 2026-06-18: `backup_database()` in wp-backup.py and DB dump loop in
wp-forensics.py both used `-p'{wp.db_pass}'`. Caught by vibe-review (CRITICAL C1).
Fixed by switching to `MYSQL_PWD='{pass_escaped}' mysqldump ...`.
