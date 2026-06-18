# Evolution Log — 2026-06-18

## Trigger
Manual `/vibe:evolve` after wp-arsenal vibe-review + fixes session.

## Rules Audited
All 5 rules at quality_score 1.0 — all kept, all promoted.

## New Harness Checks Applied

### NEW: check-credential-exposure.sh (CRITICAL priority)
**Catches:** mysqldump/mysql with `-p'...'` flag — DB password in ps output  
**Pattern:** `grep -rn "\-p'" scripts/ | grep -E "mysqldump|mysql"`  
**Why:** Caught CRITICAL C1 in review. This class of bug is easy to miss in code review
because the code looks plausible — it's the same pattern used in many tutorials.
The harness makes it unforgettable.  
**First run:** 0 findings (all fixed before this evolution ran)

### NEW: check-ssh-fstring-injection.sh (HIGH priority, non-blocking)
**Catches:** Any `.ssh(f"...")` call with f-string interpolation — potential injection  
**Mode:** Non-blocking review aid (exit 0 always) — requires human judgment per hit  
**Why:** DB-sourced values passed to shell without validation. Found 1 confirmed
injection point (whois IP from session_tokens) in review. More may exist.

### NEW: check-test-importlib.sh (MEDIUM priority)
**Catches:** Direct `from security import wp_scan` style imports of hyphenated scripts  
**Pattern:** Checks tests/ for bad imports + confirms importlib.util is used  
**Why:** 13 tests silently SKIPPED for entire session before this was caught.
Silent SKIP is worse than FAIL — it gives false confidence.  
**First run:** 0 findings (already fixed)

## CLAUDE.md / SKILL.md Changes
None this evolution — all changes are harness additions only.

## Next Evolution Triggers
- When a new script is added: run `check-ssh-fstring-injection.sh` and review output
- When test count drops: check if new scripts are missing importlib tests
- When a new DB query is added: verify it uses `sql_escape` or `sql_slug`
