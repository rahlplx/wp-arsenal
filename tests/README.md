# WP-Arsenal Test Suite

Comprehensive test coverage for wp-arsenal scripts and utilities.

## Structure

```
tests/
├── README.md                 ← this file
├── conftest.py              ← pytest fixtures + mocked SSH/SFTP
├── test_wp_connect.py       ← unit tests for sql_escape() and sql_slug()
└── test_scripts_smoke.py    ← smoke tests: script imports, mocked SSH integration
```

## Running Tests

Install test dependencies:
```bash
pip install -r ../requirements.txt
```

Run all tests:
```bash
pytest tests/
```

Run with verbose output:
```bash
pytest tests/ -v
```

Run a specific test file:
```bash
pytest tests/test_wp_connect.py -v
```

Run a specific test class:
```bash
pytest tests/test_wp_connect.py::TestSqlEscape -v
```

Run a specific test:
```bash
pytest tests/test_wp_connect.py::TestSqlEscape::test_escapes_single_quote -v
```

## Test Coverage

### Unit Tests: `test_wp_connect.py`

Tests the security-critical SQL helpers in `wp_connect.WPConnection`:

- **`sql_escape(value: str)`** — Safe SQL literal interpolation
  - Escapes single quotes (`'` → `\'`)
  - Escapes backslashes (`\` → `\\`)
  - Handles empty strings and normal input
  - Renders SQL injection attempts harmless

- **`sql_slug(value: str)`** — Slug/identifier validation
  - Accepts `[A-Za-z0-9_.-]` only
  - Rejects spaces, quotes, path traversal, special chars
  - Raises `ValueError` on invalid input
  - Used for theme slugs, usernames, identifiers that should never contain SQL metacharacters

**18 tests, all passing:**
```
test_escapes_single_quote
test_escapes_backslash
test_escapes_both_backslash_and_quote
test_empty_string
test_no_special_chars
test_multiple_quotes
test_preserves_other_special_chars
test_sql_injection_attempt_escaped
test_accepts_valid_theme_slug
test_accepts_alphanumeric_dash_underscore_dot
test_rejects_space
test_rejects_single_quote
test_rejects_sql_injection
test_rejects_path_traversal
test_rejects_special_chars
test_error_message_includes_value
test_empty_string_rejected
test_valid_slugs_used_in_wordpress
```

### Smoke Tests: `test_scripts_smoke.py`

Verifies scripts can be imported and that `WPConnection` works with mocked SSH/SFTP:

- **Import tests** — Ensure all scripts import without syntax errors
  - Security scripts (wp-scan, wp-theme-audit, wp-woo-audit)
  - Management scripts (wp-user-audit, wp-theme-switch, wp-child-theme)
  - Hardening scripts (wp-harden, wp-firewall)
  - Restoration scripts (wp-plugin-restore, wp-restore-core)
  - Forensics scripts (wp-forensics, wp-attacker-profile)
  - CI/CD scripts (wp-ci-deploy)

- **Connection tests** — Verify core `WPConnection` functionality with mocked paramiko
  - SSH command execution
  - SFTP read/write
  - MySQL query execution via SSH with base64 encoding

- **Regression prevention** — Catches bugs like:
  - `wp-backup.py` used `wp._ssh_client` instead of `wp._client` (would crash on `--output-local`)
  - Missing `_client` attribute on `WPConnection`

**24 tests passing, 13 skipped (import tests for scripts in subdirectories):**
```
test_wp_backup_ssh_client_attribute (critical regression check)
test_wpconnection_connects_with_mock
test_wpconnection_ssh_command
test_wpconnection_sftp_read
test_wpconnection_sftp_write
test_wpconnection_db_query (verifies base64 encoding of SQL)
```

## Fixtures

All fixtures are defined in `conftest.py`:

- **`mock_ssh_client`** — Patches `paramiko.SSHClient` globally so tests run without a real server
  - Provides default mocked `exec_command`, `open_sftp`, `get_transport`
  - Allows tests to configure return values per test

- **`mock_sftp`** — Mocked SFTP client (part of `mock_ssh_client`)

- **`sample_args`** — Minimal `argparse.Namespace` for `WPConnection(args)`
  - Includes SSH, WordPress, and MySQL connection details

- **`MockFileObject`** — Helper class mimicking paramiko's file-like objects
  - Takes string or bytes on init
  - Returns bytes from `.read()` (as paramiko does)
  - Allows tests to mock stdout/stderr from SSH commands

## Adding Tests

### For a new script:

1. Create a test class in `test_scripts_smoke.py` (or `test_wp_connect.py` for library functions)
2. Use the `mock_ssh_client` fixture to avoid needing a real server:
   ```python
   def test_my_script(mock_ssh_client, sample_args):
       from mymodule import my_script
       # test with mocked SSH
   ```

### For a new utility function:

1. Add unit tests to `test_wp_connect.py` (for `WPConnection` methods) or create a new test file
2. Test boundary conditions, error cases, and security properties:
   ```python
   def test_my_function():
       assert my_function("input") == "expected"
       with pytest.raises(ValueError):
           my_function("invalid")
   ```

## Key Design Decisions

- **Mocked SSH, not integration tests** — Tests run without a real server (faster, no credentials needed)
- **Security-first** — Unit tests for SQL helpers focus on injection prevention
- **Regression prevention** — Smoke tests catch the kinds of bugs that broke before
- **No doctests** — Only pytest-style tests for clarity and flexibility

## Next Steps

- Add more script-specific smoke tests (currently mostly import tests)
- Add tests for config_loader.py merging logic
- Add tests for AuditResult output formatting
- Consider coverage.py for measuring test coverage

---

**Run the test suite before every commit:**
```bash
pytest tests/ -v
```

All tests should pass (24 passed minimum, some skipped is OK).
