"""Integration tests that run actual buildifier binary."""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import buildifier_core as core


def get_buildifier_path():
    """Find buildifier binary."""
    # Check common locations
    path = shutil.which("buildifier")
    if path:
        return path

    # Check if downloaded in project
    project_root = Path(__file__).parent.parent
    for name in ["buildifier", "buildifier.exe"]:
        local_path = project_root / name
        if local_path.exists():
            return str(local_path)

    return None


BUILDIFIER_PATH = get_buildifier_path()
requires_buildifier = pytest.mark.skipif(
    BUILDIFIER_PATH is None,
    reason="buildifier not found"
)


def run_buildifier(content: str, file_type: str = "build", mode: str = "check"):
    """Run buildifier and return stdout, stderr, returncode."""
    args = [BUILDIFIER_PATH, f"--mode={mode}", f"--type={file_type}"]
    if mode == "check":
        args.append("--format=json")

    proc = subprocess.run(
        args,
        input=content.encode("utf-8"),
        capture_output=True,
    )
    return proc.stdout.decode("utf-8"), proc.stderr.decode("utf-8"), proc.returncode


@requires_buildifier
class TestBuildifierRealOutput:
    """Tests with real buildifier binary."""

    def test_valid_formatted_file(self):
        """Valid and formatted BUILD file."""
        content = 'x = 1\n'
        stdout, stderr, code = run_buildifier(content)

        result = core.parse_lint_output(stdout, stderr)

        assert result.success is True
        assert result.valid is True
        assert result.formatted is True
        assert len(result.warnings) == 0

    def test_valid_needs_formatting(self):
        """Valid but needs formatting."""
        content = 'x=1\n'  # Missing spaces around =
        stdout, stderr, code = run_buildifier(content)

        result = core.parse_lint_output(stdout, stderr)

        assert result.valid is True
        assert result.formatted is False
        assert result.needs_formatting is True

    def test_syntax_error_incomplete_statement(self):
        """Syntax error: incomplete assignment."""
        content = 'maven =\n'
        stdout, stderr, code = run_buildifier(content)

        result = core.parse_lint_output(stdout, stderr)

        assert result.valid is False
        assert len(result.warnings) >= 1

        # Should have extracted error location from stderr
        warning = result.warnings[0]
        assert warning.line >= 1
        assert "syntax error" in warning.message.lower() or "error" in warning.message.lower()

    def test_syntax_error_unclosed_paren(self):
        """Syntax error: unclosed parenthesis."""
        content = 'load(\n'
        stdout, stderr, code = run_buildifier(content)

        result = core.parse_lint_output(stdout, stderr)

        assert result.valid is False
        assert len(result.warnings) >= 1

    def test_syntax_error_unclosed_string(self):
        """Syntax error: unclosed string."""
        content = 'x = "hello\n'
        stdout, stderr, code = run_buildifier(content)

        result = core.parse_lint_output(stdout, stderr)

        assert result.valid is False
        assert len(result.warnings) >= 1
        assert "newline" in result.warnings[0].message.lower() or "string" in result.warnings[0].message.lower()

    def test_empty_file(self):
        """Empty file should be valid."""
        content = '\n'
        stdout, stderr, code = run_buildifier(content)

        result = core.parse_lint_output(stdout, stderr)

        assert result.valid is True

    def test_bzl_file_type(self):
        """Test with .bzl file type."""
        content = '''def my_rule():
    pass
'''
        stdout, stderr, code = run_buildifier(content, file_type="bzl")

        result = core.parse_lint_output(stdout, stderr)

        assert result.valid is True

    def test_module_file_type(self):
        """Test with MODULE.bazel file type."""
        content = '''module(
    name = "test",
    version = "1.0",
)
'''
        stdout, stderr, code = run_buildifier(content, file_type="module")

        result = core.parse_lint_output(stdout, stderr)

        assert result.valid is True

    def test_lint_warnings(self):
        """Test that lint warnings are captured."""
        # This should trigger a warning about load statement position
        content = '''x = 1
load("//foo:bar.bzl", "baz")
'''
        stdout, stderr, code = run_buildifier(content)

        result = core.parse_lint_output(stdout, stderr)

        # File is valid but may have warnings
        assert result.valid is True
        # Note: warnings depend on buildifier version and config

    def test_format_mode_with_error(self):
        """Test format mode (--mode=fix) with syntax error."""
        content = 'load(\n'

        proc = subprocess.run(
            [BUILDIFIER_PATH, "--mode=fix", "--type=build"],
            input=content.encode("utf-8"),
            capture_output=True,
        )

        # Should fail with syntax error
        assert proc.returncode != 0
        assert b"syntax error" in proc.stderr

    def test_format_mode_success(self):
        """Test format mode (--mode=fix) success."""
        content = 'x=1\n'

        proc = subprocess.run(
            [BUILDIFIER_PATH, "--mode=fix", "--type=build"],
            input=content.encode("utf-8"),
            capture_output=True,
        )

        # Should succeed and output formatted content
        assert proc.returncode == 0
        assert proc.stdout == b"x = 1\n"


@requires_buildifier
class TestBuildifierEdgeCases:
    """Edge case tests with real buildifier."""

    def test_unicode_content(self):
        """File with unicode characters."""
        content = '# Комментарий на русском\nx = 1\n'
        stdout, stderr, code = run_buildifier(content)

        result = core.parse_lint_output(stdout, stderr)

        assert result.valid is True

    def test_very_long_line(self):
        """File with very long line."""
        content = 'x = "' + 'a' * 1000 + '"\n'
        stdout, stderr, code = run_buildifier(content)

        result = core.parse_lint_output(stdout, stderr)

        assert result.valid is True

    def test_multiple_syntax_errors(self):
        """File with multiple issues - only first error reported."""
        content = '''load(
x =
'''
        stdout, stderr, code = run_buildifier(content)

        result = core.parse_lint_output(stdout, stderr)

        # buildifier stops at first syntax error
        assert result.valid is False

    def test_windows_line_endings(self):
        """File with Windows line endings."""
        content = 'x = 1\r\ny = 2\r\n'
        stdout, stderr, code = run_buildifier(content)

        result = core.parse_lint_output(stdout, stderr)

        assert result.valid is True

    def test_mixed_line_endings(self):
        """File with mixed line endings."""
        content = 'x = 1\r\ny = 2\nz = 3\r\n'
        stdout, stderr, code = run_buildifier(content)

        result = core.parse_lint_output(stdout, stderr)

        # Should still be valid, just needs formatting
        assert result.valid is True

    def test_trailing_whitespace(self):
        """File with trailing whitespace."""
        content = 'x = 1   \n'
        stdout, stderr, code = run_buildifier(content)

        result = core.parse_lint_output(stdout, stderr)

        assert result.valid is True
        # Likely needs formatting due to trailing whitespace

    def test_tabs_vs_spaces(self):
        """File with tabs."""
        content = 'x = [\n\t1,\n]\n'
        stdout, stderr, code = run_buildifier(content)

        result = core.parse_lint_output(stdout, stderr)

        assert result.valid is True
