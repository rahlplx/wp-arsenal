# Learnings Index — wp-arsenal

Last updated: 2026-06-18

## Patterns (reusable solutions)

| Pattern | Technology | Issue Type | Phase |
|---------|-----------|------------|-------|
| [shared-library-config-loading](patterns/shared-library-config-loading.md) | Python | Architecture | Build |
| [importlib-for-hyphenated-scripts](patterns/importlib-for-hyphenated-scripts.md) | Python / pytest | Testing | Build |
| [mysql-pwd-env-var](patterns/mysql-pwd-env-var.md) | MySQL / SSH / paramiko | Security | Build |

## Anti-Patterns (things that failed)

| Anti-Pattern | Technology | Issue Type | Severity |
|-------------|-----------|------------|---------|
| [credential-in-process-args](anti-patterns/credential-in-process-args.md) | MySQL / SSH | Security | CRITICAL |
| [str-vs-int-http-codes](anti-patterns/str-vs-int-http-codes.md) | Python / HTTP | Bug | CRITICAL |
| [user-input-in-shell-command](anti-patterns/user-input-in-shell-command.md) | SSH / paramiko | Security | HIGH |

## Projects

- [wp-arsenal-2026-06-18](projects/wp-arsenal-2026-06-18.md) — Full security toolkit build + review fixes
