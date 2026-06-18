"""
Pattern applicator — dry-run suggestions for applying mined patterns.

Checks if patterns already exist in the project and suggests where
new patterns could be added. Never auto-applies.
"""

import os
from typing import List, Dict, Any


def suggest_applications(
    okf_patterns: List[Dict[str, Any]],
    project_dir: str = ".",
) -> List[Dict[str, Any]]:
    """Suggest where OKF patterns could be applied in a project.

    Returns a list of suggestion dicts with:
    - id: pattern identifier
    - target_file: suggested file path
    - already_present: True if pattern code already exists
    - confidence: pattern confidence score
    """
    suggestions = []

    for okf in okf_patterns:
        pattern = okf.get("pattern", {})
        code = pattern.get("code", "")
        language = pattern.get("language", "")
        tags = pattern.get("tags", [])
        confidence = pattern.get("confidence", 0.0)

        target_file = _suggest_target_file(language, tags, project_dir)

        already_present = _check_code_exists(code, project_dir)

        suggestions.append({
            "id": okf.get("id", "unknown"),
            "target_file": target_file,
            "already_present": already_present,
            "confidence": confidence,
        })

    return suggestions


def _suggest_target_file(language: str, tags: List[str], project_dir: str) -> str:
    """Suggest a target file path based on language and tags."""
    if language == "php":
        if "wordpress" in tags:
            return os.path.join(project_dir, "wp-content/mu-plugins/wp-arsenal/")
        return os.path.join(project_dir, "src/")
    elif language == "python":
        if "test" in tags:
            return os.path.join(project_dir, "tests/")
        return os.path.join(project_dir, "scripts/")
    elif language == "yaml":
        return os.path.join(project_dir, "config/")
    return os.path.join(project_dir, "src/")


def _check_code_exists(code: str, project_dir: str) -> bool:
    """Check if the given code snippet already exists in the project."""
    if not code or len(code.strip()) < 10:
        return False

    normalized = " ".join(code.split())

    for root, _dirs, files in os.walk(project_dir):
        if any(part.startswith(".") or part in ("node_modules", "__pycache__", "vendor") for part in root.split(os.sep)):
            continue

        for fname in files:
            if not any(fname.endswith(ext) for ext in (".py", ".php", ".js", ".ts", ".yaml", ".yml")):
                continue

            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    file_normalized = " ".join(content.split())
                    if normalized in file_normalized:
                        return True
            except (OSError, UnicodeDecodeError):
                continue

    return False
