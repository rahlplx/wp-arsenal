"""
OKF (Our Knowledge Format) formatter.

Converts extracted Pattern objects into a standardized JSON structure
for storage, sharing, and application to other projects.
"""

from typing import List, Dict, Any
from extract import Pattern


def format_to_okf(
    pattern: Pattern,
    repo: str = "",
    license: str = "MIT",
) -> Dict[str, Any]:
    """Convert a single Pattern to OKF JSON structure.

    OKF format:
    {
        "id": "pattern-name",
        "source": {
            "repo": "owner/repo",
            "file": "path/to/file.py",
            "line_start": 1,
            "line_end": 10,
            "license": "MIT"
        },
        "pattern": {
            "type": "function_pattern",
            "language": "python",
            "code": "...",
            "description": "...",
            "tags": [...],
            "confidence": 0.9
        },
        "applicability": {
            "project_types": [],
            "relevance_score": 0.0,
            "applied": false
        }
    }
    """
    return {
        "id": pattern.name,
        "source": {
            "repo": repo,
            "file": pattern.source_file,
            "line_start": pattern.line_start,
            "line_end": pattern.line_end,
            "license": license,
        },
        "pattern": {
            "type": pattern.pattern_type,
            "language": pattern.language,
            "code": pattern.code,
            "description": pattern.description,
            "tags": pattern.tags,
            "confidence": pattern.confidence,
        },
        "applicability": {
            "project_types": [],
            "relevance_score": 0.0,
            "applied": False,
        },
    }


def format_list_to_okf(
    patterns: List[Pattern],
    repo: str = "",
    license: str = "MIT",
) -> List[Dict[str, Any]]:
    """Convert a list of Patterns to OKF format."""
    return [format_to_okf(p, repo=repo, license=license) for p in patterns]
