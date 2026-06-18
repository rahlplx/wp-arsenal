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
    project_files = _load_project_files(project_dir) if okf_patterns else []

    for okf in okf_patterns:
        pattern = okf.get("pattern", {})
        code = pattern.get("code", "")
        language = pattern.get("language", "")
        tags = pattern.get("tags", [])
        confidence = pattern.get("confidence", 0.0)

        target_file = _suggest_target_file(language, tags, project_dir)

        already_present = False
        if code and len(code.strip()) >= 10:
            normalized = " ".join(code.split())
            already_present = any(normalized in f for f in project_files)

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


def _load_project_files(project_dir: str) -> List[str]:
    """Load and normalize all source files in the project once."""
    normalized_files = []
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
                    normalized_files.append(" ".join(content.split()))
            except (OSError, UnicodeDecodeError):
                continue

    return normalized_files
