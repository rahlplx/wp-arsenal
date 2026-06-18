# Pattern: importlib for Hyphenated Python Script Files

## Problem
Python cannot import files with hyphens in their names via `import` statement:
```python
from security import wp_scan  # fails — file is wp-scan.py
```
This caused 13 smoke tests to always SKIP, giving a false sense of coverage.
All 13 were silent no-ops masked as skips.

## Solution
Use `importlib.util.spec_from_file_location()` with an explicit file path:

```python
import importlib.util

def _import_script(rel_path: str):
    full_path = os.path.join(SCRIPTS_DIR, rel_path)
    module_name = rel_path.replace("/", ".").replace("-", "_").replace(".py", "")
    spec = importlib.util.spec_from_file_location(module_name, full_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

# Usage:
mod = _import_script("security/wp-scan.py")
assert hasattr(mod, "main")
```

## When to Use
- Testing CLI scripts with hyphenated filenames (conventional in Unix tools)
- Any pytest smoke test that needs to import a file that can't be `import`ed normally

## Result
13 SKIPPED → 13 PASSING. Zero false coverage.

## Tested On
wp-arsenal, 2026-06-18
