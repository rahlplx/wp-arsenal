# Pattern: MYSQL_PWD Env Var for mysqldump/mysql Commands

## Problem
Using `-p'password'` in mysqldump/mysql commands exposes the DB password in
the remote server's process list (`ps auxf`). Any process running as the same
Unix user (e.g., a compromised WordPress PHP process) can steal it via
`/proc/*/cmdline`. On shared hosting this is a real risk.

## Solution
Use the `MYSQL_PWD` environment variable instead:

```python
pass_escaped = db_pass.replace("'", "'\\''")
cmd = f"MYSQL_PWD='{pass_escaped}' mysqldump -h '{db_host}' -u '{db_user}' '{db_name}' ..."
```

Also escape backslashes in the password (for passwords that contain `\`):
```python
pass_escaped = db_pass.replace("\\", "\\\\").replace("'", "'\\''")
```

For the `mysql` client within a `bash -c` context (like WPConnection.db()), base64-encoding
the SQL query adds another layer: shell metacharacters in query content can never be
interpreted by the remote shell:
```python
sql_b64 = base64.b64encode(sql.encode("utf-8")).decode("ascii")
cmd = (
    f"MYSQL_PWD='{pass_escaped}' bash -c '"
    f"echo {sql_b64} | base64 -d | mysql -h \"{db_host}\" -u \"{db_user}\" \"{db_name}\"'"
)
```

## When to Use
Any SSH-over-paramiko command that invokes mysql/mysqldump with credentials.
Never use `-p'...'` directly.

## Tested On
wp-arsenal, 2026-06-18 — Fixed C1 (CRITICAL) from vibe-review in wp-backup.py and wp-forensics.py
