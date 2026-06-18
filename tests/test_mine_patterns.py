#!/usr/bin/env python3
"""
Tests for the mine-patterns extraction engine.

Tests pattern extraction from Python, PHP, YAML, and test files.
"""

import pytest
import sys
import os
import tempfile
import json

# Add skills/mine-patterns to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../skills/mine-patterns"))

from extract import (
    extract_patterns_from_python,
    extract_patterns_from_php,
    extract_patterns_from_yaml,
    extract_patterns_from_tests,
    filter_by_relevance,
    Pattern,
)

from okf import format_to_okf, format_list_to_okf
from apply import suggest_applications
from feedback import add_feedback, load_feedback


class TestPatternDataclass:
    """Test the Pattern data structure."""

    def test_pattern_has_required_fields(self):
        """Pattern must have name, type, category, code, language, confidence."""
        p = Pattern(
            name="test_func",
            pattern_type="function_pattern",
            category="security",
            code="def test(): pass",
            language="python",
            confidence=0.8,
            source_file="test.py",
            line_start=1,
            line_end=1,
        )
        assert p.name == "test_func"
        assert p.pattern_type == "function_pattern"
        assert p.category == "security"
        assert p.confidence == 0.8

    def test_pattern_to_dict(self):
        """Pattern.to_dict() must return serializable dict."""
        p = Pattern(
            name="test_func",
            pattern_type="function_pattern",
            category="security",
            code="def test(): pass",
            language="python",
            confidence=0.8,
            source_file="test.py",
            line_start=1,
            line_end=1,
        )
        d = p.to_dict()
        assert isinstance(d, dict)
        assert d["name"] == "test_func"
        assert json.dumps(d)  # Must be JSON-serializable


class TestExtractFromPython:
    """Test Python function and class extraction."""

    def test_extracts_simple_function(self):
        """Should extract a simple function definition."""
        code = '''
def sql_escape(value: str) -> str:
    """Escape single quotes for SQL."""
    return value.replace("'", "\\\\'")
'''
        patterns = extract_patterns_from_python(code, "test.py")
        assert len(patterns) >= 1
        names = [p.name for p in patterns]
        assert "sql_escape" in names

    def test_extracts_class_with_methods(self):
        """Should extract class definitions."""
        code = '''
class WPConnection:
    """SSH connection manager."""

    def __init__(self, host: str):
        self.host = host

    def connect(self):
        pass
'''
        patterns = extract_patterns_from_python(code, "test.py")
        class_patterns = [p for p in patterns if p.pattern_type == "class_pattern"]
        assert len(class_patterns) >= 1
        assert class_patterns[0].name == "WPConnection"

    def test_extracts_context_manager(self):
        """Should detect context manager patterns (with statement)."""
        code = '''
class Connection:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
'''
        patterns = extract_patterns_from_python(code, "test.py")
        cm_patterns = [p for p in patterns if "context" in p.category.lower() or "__enter__" in p.code]
        assert len(cm_patterns) >= 1

    def test_does_not_extract_class_methods_twice(self):
        """Class methods should not appear as standalone functions."""
        code = '''
class WPConnection:
    def connect(self):
        pass

    def disconnect(self):
        pass
'''
        patterns = extract_patterns_from_python(code, "test.py")
        func_names = [p.name for p in patterns if p.pattern_type == "function_pattern"]
        assert "connect" not in func_names
        assert "disconnect" not in func_names

    def test_extracts_decorated_function(self):
        """Should extract decorated functions."""
        code = '''
@pytest.fixture
def mock_ssh_client():
    """Mock SSH client."""
    return MagicMock()
'''
        patterns = extract_patterns_from_python(code, "test.py")
        assert len(patterns) >= 1
        assert any("mock_ssh_client" in p.name for p in patterns)

    def test_ignores_private_functions(self):
        """Should not extract functions starting with _ (internal)."""
        code = '''
def _internal_helper():
    pass

def public_api():
    pass
'''
        patterns = extract_patterns_from_python(code, "test.py")
        names = [p.name for p in patterns]
        assert "_internal_helper" not in names
        assert "public_api" in names

    def test_extracts_docstring(self):
        """Should capture function docstring as description."""
        code = '''
def sql_escape(value: str) -> str:
    """Escape single quotes for safe SQL interpolation."""
    return value
'''
        patterns = extract_patterns_from_python(code, "test.py")
        assert len(patterns) >= 1
        assert "Escape single quotes" in patterns[0].description

    def test_handles_syntax_errors_gracefully(self):
        """Should not crash on invalid Python syntax."""
        code = '''
def broken(
    this is not valid python
    ????
'''
        patterns = extract_patterns_from_python(code, "test.py")
        assert isinstance(patterns, list)


class TestExtractFromPHP:
    """Test PHP MU-plugin pattern extraction."""

    def test_extracts_plugin_header(self):
        """Should extract WordPress plugin metadata."""
        code = '''<?php
/**
 * Plugin Name: WP-Arsenal IP Blocker
 * Description: PHP-level IP block list
 * Deploy to: wp-content/mu-plugins/ip-blocker.php
 */

defined( 'ABSPATH' ) || exit;
'''
        patterns = extract_patterns_from_php(code, "ip-blocker.php")
        assert len(patterns) >= 1
        assert any("IP Blocker" in p.name for p in patterns)

    def test_extracts_add_action_hooks(self):
        """Should extract WordPress hook registrations."""
        code = '''<?php
add_action('init', 'my_init_function');
add_filter('the_content', 'my_content_filter');
'''
        patterns = extract_patterns_from_php(code, "hooks.php")
        hook_patterns = [p for p in patterns if "hook" in p.category.lower() or "add_" in p.code]
        assert len(hook_patterns) >= 1

    def test_extracts_config_loading_pattern(self):
        """Should detect config loading via ABSPATH or __DIR__."""
        code = '''<?php
$config = __DIR__ . '/wp-arsenal-config.php';
if (file_exists($config)) {
    require_once $config;
}
'''
        patterns = extract_patterns_from_php(code, "plugin.php")
        config_patterns = [p for p in patterns if "config" in p.category.lower()]
        assert len(config_patterns) >= 1

    def test_extracts_capability_checks(self):
        """Should detect current_user_can() security patterns."""
        code = '''<?php
if (current_user_can('manage_options')) {
    // admin action
}
'''
        patterns = extract_patterns_from_php(code, "admin.php")
        security_patterns = [p for p in patterns if "security" in p.category.lower() or "capability" in p.code.lower()]
        assert len(security_patterns) >= 1


class TestExtractFromYAML:
    """Test YAML config pattern extraction."""

    def test_extracts_ssh_config_structure(self):
        """Should extract SSH config patterns from YAML."""
        yaml_content = '''
ssh:
  host: "example.com"
  user: "admin"
  port: 22
  timeout: 30
'''
        patterns = extract_patterns_from_yaml(yaml_content, "config.yaml")
        assert len(patterns) >= 1
        assert any("ssh" in p.name.lower() or "ssh" in p.category.lower() for p in patterns)

    def test_extracts_database_config(self):
        """Should extract database config patterns."""
        yaml_content = '''
database:
  host: "localhost"
  user: "wpuser"
  name: "wordpress"
'''
        patterns = extract_patterns_from_yaml(yaml_content, "config.yaml")
        assert len(patterns) >= 1

    def test_handles_invalid_yaml(self):
        """Should not crash on invalid YAML."""
        yaml_content = '''
ssh:
  host: [invalid yaml
    broken:
'''
        patterns = extract_patterns_from_yaml(yaml_content, "config.yaml")
        assert isinstance(patterns, list)


class TestExtractFromTests:
    """Test test file pattern extraction."""

    def test_extracts_test_class(self):
        """Should extract test class patterns."""
        code = '''
class TestSqlEscape:
    """Test SQL escaping."""

    def test_escapes_single_quote(self):
        assert WPConnection.sql_escape("O'Brien") == "O\\'Brien"
'''
        patterns = extract_patterns_from_tests(code, "test_wp_connect.py")
        assert len(patterns) >= 1
        assert any("TestSqlEscape" in p.name for p in patterns)

    def test_extracts_fixture(self):
        """Should extract pytest fixture patterns."""
        code = '''
@pytest.fixture
def mock_ssh_client():
    """Mock SSH client for testing."""
    return MagicMock()
'''
        patterns = extract_patterns_from_tests(code, "conftest.py")
        fixture_patterns = [p for p in patterns if "fixture" in p.tags]
        assert len(fixture_patterns) >= 1

    def test_extracts_parametrize(self):
        """Should extract parametrized test patterns."""
        code = '''
@pytest.mark.parametrize("input,expected", [
    ("O'Brien", "O\\\\'Brien"),
    ("test", "test"),
])
def test_sql_escape(input, expected):
    assert WPConnection.sql_escape(input) == expected
'''
        patterns = extract_patterns_from_tests(code, "test_wp_connect.py")
        assert len(patterns) >= 1


class TestFilterByRelevance:
    """Test relevance filtering."""

    def test_filters_by_keyword(self):
        """Should only return patterns matching focus keywords."""
        patterns = [
            Pattern("ssh_connect", "function_pattern", "security", "def ssh(): pass", "python", 0.9, "a.py", 1, 1),
            Pattern("color_print", "function_pattern", "cli", "def red(): pass", "python", 0.8, "b.py", 1, 1),
            Pattern("sql_escape", "function_pattern", "security", "def esc(): pass", "python", 0.9, "c.py", 1, 1),
        ]
        filtered = filter_by_relevance(patterns, ["security", "ssh"])
        assert len(filtered) == 2
        names = [p.name for p in filtered]
        assert "ssh_connect" in names
        assert "sql_escape" in names
        assert "color_print" not in names

    def test_returns_all_when_no_filter(self):
        """Should return all patterns when no keywords specified."""
        patterns = [
            Pattern("a", "function_pattern", "security", "code", "python", 0.9, "a.py", 1, 1),
            Pattern("b", "function_pattern", "cli", "code", "python", 0.8, "b.py", 1, 1),
        ]
        filtered = filter_by_relevance(patterns, [])
        assert len(filtered) == 2

    def test_case_insensitive_matching(self):
        """Keyword matching should be case-insensitive."""
        patterns = [
            Pattern("SSH_connect", "function_pattern", "SSH", "code", "python", 0.9, "a.py", 1, 1),
        ]
        filtered = filter_by_relevance(patterns, ["ssh"])
        assert len(filtered) == 1


class TestOKFFormatter:
    """Test OKF (Our Knowledge Format) output."""

    def test_format_single_pattern(self):
        """Should convert a Pattern to OKF JSON structure."""
        p = Pattern("ssh_connect", "function_pattern", "security", "def ssh(): pass", "python", 0.9, "scripts/wp_connect.py", 10, 15)
        okf = format_to_okf(p, repo="owner/repo", license="MIT")
        assert okf["id"] == "ssh_connect"
        assert okf["source"]["repo"] == "owner/repo"
        assert okf["source"]["file"] == "scripts/wp_connect.py"
        assert okf["source"]["line_start"] == 10
        assert okf["source"]["line_end"] == 15
        assert okf["source"]["license"] == "MIT"
        assert okf["pattern"]["type"] == "function_pattern"
        assert okf["pattern"]["language"] == "python"
        assert okf["pattern"]["code"] == "def ssh(): pass"
        assert okf["pattern"]["confidence"] == 0.9
        assert okf["applicability"]["applied"] is False

    def test_format_includes_tags(self):
        """Should include tags in OKF output."""
        p = Pattern("sql_escape", "function_pattern", "security", "code", "python", 0.9, "a.py", 1, 1, tags=["security", "sql"])
        okf = format_to_okf(p, repo="r", license="MIT")
        assert okf["pattern"]["tags"] == ["security", "sql"]

    def test_format_includes_description(self):
        """Should include description in OKF output."""
        p = Pattern("x", "function_pattern", "c", "code", "python", 0.9, "a.py", 1, 1, description="Escapes SQL")
        okf = format_to_okf(p, repo="r", license="MIT")
        assert okf["pattern"]["description"] == "Escapes SQL"

    def test_format_list(self):
        """Should format a list of patterns into a list of OKF objects."""
        patterns = [
            Pattern("a", "function_pattern", "c", "code_a", "python", 0.9, "a.py", 1, 1),
            Pattern("b", "class_pattern", "c", "code_b", "python", 0.8, "b.py", 5, 10),
        ]
        okf_list = format_list_to_okf(patterns, repo="r", license="MIT")
        assert len(okf_list) == 2
        assert okf_list[0]["id"] == "a"
        assert okf_list[1]["id"] == "b"

    def test_format_json_serializable(self):
        """Output should be JSON-serializable."""
        import json
        p = Pattern("test", "function_pattern", "c", "code", "python", 0.9, "a.py", 1, 1)
        okf = format_to_okf(p, repo="r", license="MIT")
        serialized = json.dumps(okf)
        assert "test" in serialized

    def test_format_empty_list(self):
        """Should handle empty pattern list."""
        result = format_list_to_okf([], repo="r", license="MIT")
        assert result == []


class TestApplicator:
    """Test pattern applicator (dry-run suggestions)."""

    def test_suggest_returns_list(self):
        """Should return a list of suggestions from OKF patterns."""
        okf = [{
            "id": "ssh_connect",
            "source": {"repo": "r", "file": "a.py", "line_start": 1, "line_end": 5, "license": "MIT"},
            "pattern": {"type": "function_pattern", "language": "python", "code": "def ssh_connect(): pass", "description": "SSH connection", "tags": ["ssh"], "confidence": 0.9},
            "applicability": {"project_types": [], "relevance_score": 0.0, "applied": False},
        }]
        suggestions = suggest_applications(okf, project_dir=".")
        assert isinstance(suggestions, list)

    def test_suggest_marks_duplicates(self):
        """Should mark patterns already present in project as duplicates."""
        import tempfile, os
        tmpdir = tempfile.mkdtemp()
        code_snippet = "def unique_check_dup_test_func(): pass"
        fpath = os.path.join(tmpdir, "test_dup.py")
        with open(fpath, "w") as f:
            f.write(code_snippet)
        okf = [{
            "id": "dup_test",
            "source": {"repo": "r", "file": "a.py", "line_start": 1, "line_end": 3, "license": "MIT"},
            "pattern": {"type": "function_pattern", "language": "python", "code": code_snippet, "description": "Dup test", "tags": [], "confidence": 0.9},
            "applicability": {"project_types": [], "relevance_score": 0.0, "applied": False},
        }]
        suggestions = suggest_applications(okf, project_dir=tmpdir)
        assert len(suggestions) == 1
        assert suggestions[0]["already_present"] is True
        import shutil
        shutil.rmtree(tmpdir)

    def test_suggest_empty_patterns(self):
        """Should return empty list for no patterns."""
        suggestions = suggest_applications([], project_dir=".")
        assert suggestions == []

    def test_suggest_includes_target_file(self):
        """Suggestion should include a target file path for the pattern."""
        okf = [{
            "id": "test_pattern",
            "source": {"repo": "r", "file": "src/utils.py", "line_start": 1, "line_end": 3, "license": "MIT"},
            "pattern": {"type": "function_pattern", "language": "python", "code": "def util(): pass", "description": "Utility", "tags": [], "confidence": 0.8},
            "applicability": {"project_types": [], "relevance_score": 0.0, "applied": False},
        }]
        suggestions = suggest_applications(okf, project_dir=".")
        assert len(suggestions) == 1
        assert "target_file" in suggestions[0]


class TestFeedbackStore:
    """Test pattern feedback tracking."""

    def test_add_feedback(self):
        """Should add a feedback entry for a pattern."""
        import tempfile, os
        tmpdir = tempfile.mkdtemp()
        store_path = os.path.join(tmpdir, "mined-patterns.json")
        add_feedback(store_path, pattern_id="ssh_connect", status="accepted", notes="Great pattern")
        data = load_feedback(store_path)
        assert len(data) == 1
        assert data[0]["id"] == "ssh_connect"
        assert data[0]["status"] == "accepted"
        assert data[0]["notes"] == "Great pattern"
        import shutil
        shutil.rmtree(tmpdir)

    def test_add_multiple_feedback(self):
        """Should accumulate multiple feedback entries."""
        import tempfile, os
        tmpdir = tempfile.mkdtemp()
        store_path = os.path.join(tmpdir, "mined-patterns.json")
        add_feedback(store_path, pattern_id="a", status="accepted")
        add_feedback(store_path, pattern_id="b", status="rejected")
        data = load_feedback(store_path)
        assert len(data) == 2
        ids = [d["id"] for d in data]
        assert "a" in ids
        assert "b" in ids
        import shutil
        shutil.rmtree(tmpdir)

    def test_load_empty_store(self):
        """Should return empty list for non-existent store."""
        data = load_feedback("/nonexistent/path/mined-patterns.json")
        assert data == []

    def test_reject_overwrites_previous(self):
        """Should update status if same pattern ID feedback added again."""
        import tempfile, os
        tmpdir = tempfile.mkdtemp()
        store_path = os.path.join(tmpdir, "mined-patterns.json")
        add_feedback(store_path, pattern_id="x", status="accepted")
        add_feedback(store_path, pattern_id="x", status="rejected")
        data = load_feedback(store_path)
        assert len(data) == 1
        assert data[0]["status"] == "rejected"
        import shutil
        shutil.rmtree(tmpdir)


class TestEndToEndPipeline:
    """Integration test: extract → OKF → apply → feedback."""

    def test_full_pipeline(self):
        """Should extract patterns, format to OKF, suggest applications, track feedback."""
        import tempfile, os

        # 1. Extract patterns from Python code
        code = '''
def sql_escape(value):
    """Escape SQL string to prevent injection."""
    return value.replace("'", "\\\\'")

def ssh_connect(host, port=22):
    """Establish SSH connection to remote host."""
    import paramiko
    client = paramiko.SSHClient()
    client.connect(host, port=port)
    return client
'''
        patterns = extract_patterns_from_python(code, "scripts/test_module.py")
        assert len(patterns) >= 2

        # 2. Format to OKF
        okf_list = format_list_to_okf(patterns, repo="test/repo", license="MIT")
        assert len(okf_list) == len(patterns)
        assert okf_list[0]["source"]["repo"] == "test/repo"

        # 3. Suggest applications
        tmpdir = tempfile.mkdtemp()
        suggestions = suggest_applications(okf_list, project_dir=tmpdir)
        assert len(suggestions) == len(patterns)
        for s in suggestions:
            assert "target_file" in s
            assert "already_present" in s

        # 4. Track feedback
        store_path = os.path.join(tmpdir, "mined-patterns.json")
        for okf in okf_list:
            add_feedback(store_path, pattern_id=okf["id"], status="accepted")
        feedback = load_feedback(store_path)
        assert len(feedback) == len(okf_list)
        assert all(f["status"] == "accepted" for f in feedback)

        import shutil
        shutil.rmtree(tmpdir)
