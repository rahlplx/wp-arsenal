# Skill: Mine Patterns

**Trigger:** "mine patterns from [repos]", "learn from [project]", "enhance with [repo]", "discover patterns"

## Purpose

Automatically discover, extract, and document proven patterns from other open-source repositories, then suggest actionable improvements to wp-arsenal.

## Input

```
repos: List[str]           # GitHub repos to mine (e.g., "fabric/fabric", "PyCQA/bandit")
focus: str                  # Domain focus (e.g., "security", "cli", "testing", "all")
output_dir: str = "docs/mined-patterns"  # Where to write OKF reports
auto_apply: bool = False    # Never true in v1 — human review required
```

## Output

1. **OKF Report** — `docs/mined-patterns/{repo-name}.json` (JSON-LD format)
2. **Actionable Tasks** — Summary of suggested improvements
3. **Feedback Log** — `docs/mined-patterns.json` (tracks applied/rejected patterns)

## Workflow

### Phase 1: Discovery
```bash
# Clone or read repos via GitHub API
python skills/mine-patterns/extract.py \
    --repos fabric/fabric,PyCQA/bandit \
    --focus security \
    --output docs/mined-patterns/
```

### Phase 2: Extraction
For each repo, extract patterns by type:
- `function_pattern` — Reusable functions with clear interfaces
- `class_pattern` — Class designs with good encapsulation
- `config_pattern` — Configuration structures and loading
- `test_pattern` — Test organization and fixtures
- `ci_pattern` — CI/CD pipeline configurations

### Phase 3: OKF Formatting
Convert extracted patterns to Open Knowledge Format:
```json
{
    "@context": "https://schema.org",
    "@type": "CodePattern",
    "name": "Connection context manager",
    "description": "Fabric's SSH connection with automatic cleanup",
    "codeLanguage": "python",
    "source": {
        "@type": "SoftwareSourceCode",
        "codeRepository": "https://github.com/fabric/fabric",
        "license": "https://opensource.org/licenses/BSD-2-Clause"
    },
    "pattern": {
        "type": "class_pattern",
        "category": "connection_management",
        "confidence": 0.95,
        "relevance": ["ssh", "connection", "context-manager"]
    },
    "example": {
        "code": "with Connection('host') as c:\n    c.run('cmd')",
        "language": "python"
    }
}
```

### Phase 4: Application
Read OKF reports and suggest changes:
```bash
python skills/mine-patterns/apply.py \
    --input docs/mined-patterns/ \
    --target scripts/
```

## Safety Rules

1. **Human review required** — No auto-apply in v1
2. **License check** — Only mine from MIT/Apache-2.0/BSD repos
3. **Pattern safety** — Flag exec/eval/subprocess patterns for manual review
4. **Attribution** — Source repo and license in every OKF entry
5. **Rollback** — Each applied pattern is a separate git commit

## Pattern Categories

| Category | Description | Examples |
|----------|-------------|----------|
| `security` | Security patterns, input validation, auth | SQL escaping, CSRF protection |
| `connection` | SSH, HTTP, database connections | Context managers, connection pools |
| `cli` | CLI design, argument parsing, output | Color handling, TTY detection |
| `testing` | Test structure, fixtures, mocking | Shared fixtures, parametrize |
| `config` | Configuration loading, validation | YAML loading, env var fallback |
| `error_handling` | Error patterns, logging, recovery | Try/except, retry logic |
| `signature` | Malware signatures, pattern matching | Regex patterns, YARA rules |
| `php` | WordPress PHP patterns | MU-plugins, hooks, capabilities |

## Feedback Loop

Track pattern adoption in `docs/mined-patterns.json`:
```json
{
    "patterns": [
        {
            "id": "fabric-context-manager",
            "source": "fabric/fabric",
            "status": "applied",
            "commit": "abc123",
            "date": "2026-06-19",
            "notes": "Applied to wp_connect.py SSH methods"
        }
    ]
}
```

## Integration with Vibe Workflow

- **`/vibe:plan`** — Mine patterns before planning to inform architecture decisions
- **`/vibe:build`** — Apply mined patterns during implementation
- **`/vibe:review`** — Verify applied patterns match source quality
- **`/vibe:harness`** — Add harness checks for mined pattern compliance
