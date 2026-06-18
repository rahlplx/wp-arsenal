"""
extract.py — Pattern extraction engine for mine-patterns skill.

Extracts code patterns from Python, PHP, YAML, and test files.
Returns structured Pattern objects for OKF formatting.
"""

import re
import ast
from dataclasses import dataclass, field, asdict
from typing import List


@dataclass
class Pattern:
    """A extracted code pattern."""
    name: str
    pattern_type: str  # function_pattern, class_pattern, config_pattern, test_pattern, ci_pattern
    category: str      # security, connection, cli, testing, config, error_handling, signature, php
    code: str
    language: str
    confidence: float
    source_file: str
    line_start: int
    line_end: int
    description: str = ""
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to JSON-serializable dict."""
        return asdict(self)


def _safe_parse_python(code: str):
    """Parse Python code, return AST or None on syntax error."""
    try:
        return ast.parse(code)
    except SyntaxError:
        return None


def _extract_docstring(node) -> str:
    """Extract docstring from an AST node."""
    if hasattr(ast, "get_docstring"):
        doc = ast.get_docstring(node)
        if doc:
            return doc.split("\n")[0]  # First line only
    return ""


def _classify_function(name: str, code: str) -> str:
    """Classify a function into a category based on name and code."""
    name_lower = name.lower()
    code_lower = code.lower()

    if any(kw in name_lower for kw in ["ssh", "connect", "sftp", "db", "mysql"]):
        return "connection"
    if any(kw in name_lower for kw in ["escape", "sanitize", "validate", "auth", "security"]):
        return "security"
    if any(kw in name_lower for kw in ["color", "print", "output", "format", "display"]):
        return "cli"
    if any(kw in name_lower for kw in ["load", "config", "parse", "read_yaml"]):
        return "config"
    if any(kw in name_lower for kw in ["test_", "mock_", "fixture"]):
        return "testing"
    if any(kw in code_lower for kw in ["try:", "except", "raise", "error"]):
        return "error_handling"
    return "general"


def extract_patterns_from_python(code: str, source_file: str) -> List[Pattern]:
    """Extract function and class patterns from Python code."""
    patterns = []
    tree = _safe_parse_python(code)
    if tree is None:
        return patterns

    lines = code.split("\n")

    class_methods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for child in ast.walk(node):
                if child is not node and isinstance(child, ast.FunctionDef):
                    class_methods.add(child)

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            if node.name.startswith("_") or node in class_methods:
                continue

            start = node.lineno
            end = getattr(node, "end_lineno", start)
            func_code = "\n".join(lines[start - 1:end])
            docstring = _extract_docstring(node)
            category = _classify_function(node.name, func_code)

            if "__enter__" in func_code or "__exit__" in func_code:
                category = "connection"

            patterns.append(Pattern(
                name=node.name,
                pattern_type="function_pattern",
                category=category,
                code=func_code,
                language="python",
                confidence=0.8,
                source_file=source_file,
                line_start=start,
                line_end=end,
                description=docstring,
            ))

        elif isinstance(node, ast.ClassDef):
            start = node.lineno
            end = getattr(node, "end_lineno", start)
            class_code = "\n".join(lines[start - 1:end])
            docstring = _extract_docstring(node)

            has_enter = any(
                isinstance(n, ast.FunctionDef) and n.name == "__enter__"
                for n in ast.walk(node)
            )
            category = "connection" if has_enter else "general"

            patterns.append(Pattern(
                name=node.name,
                pattern_type="class_pattern",
                category=category,
                code=class_code,
                language="python",
                confidence=0.85,
                source_file=source_file,
                line_start=start,
                line_end=end,
                description=docstring,
            ))

    return patterns


def extract_patterns_from_php(code: str, source_file: str) -> List[Pattern]:
    """Extract WordPress MU-plugin patterns from PHP code."""
    patterns = []
    lines = code.split("\n")

    header_match = re.search(r'/\*\*.*?Plugin Name:\s*(.+?)[\n*]', code, re.DOTALL)
    if header_match:
        plugin_name = header_match.group(1).strip().rstrip("*").strip()
        patterns.append(Pattern(
            name=plugin_name,
            pattern_type="config_pattern",
            category="php",
            code=code[:500],
            language="php",
            confidence=0.9,
            source_file=source_file,
            line_start=1,
            line_end=min(10, len(lines)),
            description=f"WordPress MU-plugin: {plugin_name}",
            tags=["wordpress", "mu-plugin"],
        ))

    for i, line in enumerate(lines, 1):
        hook_match = re.search(r"add_(action|filter)\s*\(\s*['\"]([^'\"]+)['\"]", line)
        if hook_match:
            hook_type = hook_match.group(1)
            hook_name = hook_match.group(2)
            patterns.append(Pattern(
                name=f"{hook_type}:{hook_name}",
                pattern_type="function_pattern",
                category="php",
                code=line.strip(),
                language="php",
                confidence=0.85,
                source_file=source_file,
                line_start=i,
                line_end=i,
                description=f"WordPress {hook_type} on {hook_name}",
                tags=["wordpress", "hook", hook_type],
            ))

        if re.search(r"(__DIR__|ABSPATH).*config", line, re.IGNORECASE):
            patterns.append(Pattern(
                name="config-loading",
                pattern_type="config_pattern",
                category="config",
                code=line.strip(),
                language="php",
                confidence=0.8,
                source_file=source_file,
                line_start=i,
                line_end=i,
                description="Config file loading pattern",
                tags=["config", "loading"],
            ))

        cap_match = re.search(r"current_user_can\s*\(\s*['\"]([^'\"]+)['\"]", line)
        if cap_match:
            capability = cap_match.group(1)
            patterns.append(Pattern(
                name=f"capability:{capability}",
                pattern_type="function_pattern",
                category="security",
                code=line.strip(),
                language="php",
                confidence=0.9,
                source_file=source_file,
                line_start=i,
                line_end=i,
                description=f"WordPress capability check: {capability}",
                tags=["security", "capability", "wordpress"],
            ))

    return patterns


def extract_patterns_from_yaml(code: str, source_file: str) -> List[Pattern]:
    """Extract configuration patterns from YAML code."""
    patterns = []
    lines = code.split("\n")

    current_section = None
    section_lines = []
    section_start = 0

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if not line.startswith(" ") and not line.startswith("\t") and ":" in stripped:
            if current_section and section_lines:
                patterns.append(Pattern(
                    name=current_section,
                    pattern_type="config_pattern",
                    category="config",
                    code="\n".join(section_lines),
                    language="yaml",
                    confidence=0.7,
                    source_file=source_file,
                    line_start=section_start,
                    line_end=i - 1,
                    description=f"YAML config section: {current_section}",
                    tags=["config", "yaml"],
                ))

            current_section = stripped.split(":")[0].strip()
            section_lines = [line]
            section_start = i
        elif current_section:
            section_lines.append(line)

    if current_section and section_lines:
        patterns.append(Pattern(
            name=current_section,
            pattern_type="config_pattern",
            category="config",
            code="\n".join(section_lines),
            language="yaml",
            confidence=0.7,
            source_file=source_file,
            line_start=section_start,
            line_end=len(lines),
            description=f"YAML config section: {current_section}",
            tags=["config", "yaml"],
        ))

    return patterns


def extract_patterns_from_tests(code: str, source_file: str) -> List[Pattern]:
    """Extract test patterns (classes, fixtures, parametrize)."""
    patterns = []
    tree = _safe_parse_python(code)
    if tree is None:
        return patterns

    lines = code.split("\n")

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            start = node.lineno
            end = getattr(node, "end_lineno", start)
            class_code = "\n".join(lines[start - 1:end])
            docstring = _extract_docstring(node)

            patterns.append(Pattern(
                name=node.name,
                pattern_type="test_pattern",
                category="testing",
                code=class_code,
                language="python",
                confidence=0.85,
                source_file=source_file,
                line_start=start,
                line_end=end,
                description=docstring,
                tags=["test", "class"],
            ))

        elif isinstance(node, ast.FunctionDef):
            extracted = False
            for decorator in node.decorator_list:
                if extracted:
                    break

                dec_name = ""
                if isinstance(decorator, ast.Name):
                    dec_name = decorator.id
                elif isinstance(decorator, ast.Attribute):
                    dec_name = decorator.attr
                elif isinstance(decorator, ast.Call):
                    func = decorator.func
                    if isinstance(func, ast.Attribute):
                        dec_name = func.attr
                    elif isinstance(func, ast.Name):
                        dec_name = func.id

                if dec_name == "fixture":
                    start = decorator.lineno
                    end = getattr(node, "end_lineno", node.lineno)
                    func_code = "\n".join(lines[start - 1:end])
                    docstring = _extract_docstring(node)

                    patterns.append(Pattern(
                        name=node.name,
                        pattern_type="test_pattern",
                        category="testing",
                        code=func_code,
                        language="python",
                        confidence=0.9,
                        source_file=source_file,
                        line_start=start,
                        line_end=end,
                        description=docstring,
                        tags=["test", "fixture"],
                    ))
                    extracted = True

                elif dec_name == "parametrize":
                    start = decorator.lineno
                    end = getattr(node, "end_lineno", node.lineno)
                    func_code = "\n".join(lines[start - 1:end])

                    patterns.append(Pattern(
                        name=f"parametrize:{node.name}",
                        pattern_type="test_pattern",
                        category="testing",
                        code=func_code,
                        language="python",
                        confidence=0.85,
                        source_file=source_file,
                        line_start=start,
                        line_end=end,
                        description=f"Parametrized test: {node.name}",
                        tags=["test", "parametrize"],
                    ))
                    extracted = True

    return patterns


def filter_by_relevance(patterns: List[Pattern], keywords: List[str]) -> List[Pattern]:
    """Filter patterns by relevance keywords (case-insensitive)."""
    if not keywords:
        return patterns

    keywords_lower = [k.lower() for k in keywords]
    return [
        p for p in patterns
        if any(
            kw in p.name.lower()
            or kw in p.category.lower()
            or kw in p.description.lower()
            or any(kw in tag.lower() for tag in p.tags)
            for kw in keywords_lower
        )
    ]
