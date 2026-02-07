"""Tests for buildifier_core module."""

import hashlib
import json
from pathlib import Path
from typing import Optional

import pytest

import buildifier_core as core


# ============================================================================
# File Type Detection Tests
# ============================================================================


class TestIsBazelFile:
    """Tests for is_bazel_file function."""

    @pytest.mark.parametrize(
        "filename,expected",
        [
            ("BUILD", True),
            ("BUILD.bazel", True),
            ("BUILD.oss", True),
            ("WORKSPACE", True),
            ("WORKSPACE.bazel", True),
            ("MODULE.bazel", True),
            ("foo.bzl", True),
            ("foo.bzl.oss", True),
            ("rules.bzl", True),
            ("README.md", False),
            ("main.py", False),
            ("Makefile", False),
            ("build", False),  # lowercase
            ("workspace", False),  # lowercase
        ],
    )
    def test_standard_files(self, filename: str, expected: bool) -> None:
        assert core.is_bazel_file(filename) == expected

    def test_additional_patterns(self) -> None:
        additional = {"*.star": "default", "DEPS": "build"}
        assert core.is_bazel_file("foo.star", additional) is True
        assert core.is_bazel_file("DEPS", additional) is True
        assert core.is_bazel_file("deps", additional) is False


class TestGetFileType:
    """Tests for get_file_type function."""

    @pytest.mark.parametrize(
        "filename,expected",
        [
            ("BUILD", "build"),
            ("BUILD.bazel", "build"),
            ("BUILD.oss", "build"),
            ("WORKSPACE", "workspace"),
            ("WORKSPACE.bazel", "workspace"),
            ("MODULE.bazel", "module"),
            ("foo.bzl", "bzl"),
            ("foo.bzl.oss", "bzl"),
            ("README.md", None),
        ],
    )
    def test_standard_types(self, filename: str, expected: Optional[str]) -> None:
        assert core.get_file_type(filename) == expected

    def test_additional_patterns_type(self) -> None:
        additional = {"*.star": "default", "DEPS": "build"}
        assert core.get_file_type("foo.star", additional) == "default"
        assert core.get_file_type("DEPS", additional) == "build"

    def test_path_with_directories(self) -> None:
        # Should work with paths, extracting basename
        assert core.get_file_type("/path/to/BUILD") == "build"
        assert core.get_file_type("src/lib/rules.bzl") == "bzl"


class TestMatchGlobPattern:
    """Tests for _match_glob_pattern function."""

    @pytest.mark.parametrize(
        "filename,pattern,expected",
        [
            ("BUILD", "BUILD", True),
            ("foo.star", "*.star", True),
            ("bar.star", "*.star", True),
            ("foo.bzl", "*.star", False),
            ("DEPS", "DEPS", True),
            ("deps", "DEPS", False),
            ("test.foo.bar", "*.foo.*", True),
        ],
    )
    def test_patterns(self, filename: str, pattern: str, expected: bool) -> None:
        assert core._match_glob_pattern(filename, pattern) == expected


# ============================================================================
# Platform Detection Tests
# ============================================================================


class TestGetPlatformInfo:
    """Tests for get_platform_info function."""

    @pytest.mark.parametrize(
        "sys_platform,machine,expected_os,expected_arch",
        [
            ("darwin", "arm64", "darwin", "arm64"),
            ("darwin", "x86_64", "darwin", "amd64"),
            ("linux", "x86_64", "linux", "amd64"),
            ("linux", "aarch64", "linux", "arm64"),
            ("win32", "AMD64", "windows", "amd64"),
            ("win32", "ARM64", "windows", "arm64"),
        ],
    )
    def test_supported_platforms(
        self, sys_platform: str, machine: str, expected_os: str, expected_arch: str
    ) -> None:
        os_name, arch = core.get_platform_info(system=sys_platform, machine=machine)
        assert os_name == expected_os
        assert arch == expected_arch

    def test_unsupported_platform(self) -> None:
        with pytest.raises(ValueError, match="Unsupported platform"):
            core.get_platform_info(system="freebsd", machine="x86_64")

    def test_unsupported_architecture(self) -> None:
        with pytest.raises(ValueError, match="Unsupported architecture"):
            core.get_platform_info(system="linux", machine="i386")


class TestGetAssetName:
    """Tests for get_asset_name function."""

    @pytest.mark.parametrize(
        "os_name,arch,expected",
        [
            ("darwin", "arm64", "buildifier-darwin-arm64"),
            ("darwin", "amd64", "buildifier-darwin-amd64"),
            ("linux", "amd64", "buildifier-linux-amd64"),
            ("linux", "arm64", "buildifier-linux-arm64"),
            ("windows", "amd64", "buildifier-windows-amd64.exe"),
            ("windows", "arm64", "buildifier-windows-arm64.exe"),
        ],
    )
    def test_asset_names(self, os_name: str, arch: str, expected: str) -> None:
        assert core.get_asset_name(os_name, arch) == expected


# ============================================================================
# Config Directory Tests
# ============================================================================


class TestFindConfigDir:
    """Tests for find_config_dir function."""

    def test_config_in_current_dir(self, tmp_path: Path) -> None:
        config_file = tmp_path / ".buildifier.json"
        config_file.write_text("{}")

        test_file = tmp_path / "BUILD"
        test_file.write_text("")

        result = core.find_config_dir(str(test_file))
        assert result == str(tmp_path)

    def test_config_in_parent_dir(self, tmp_path: Path) -> None:
        config_file = tmp_path / ".buildifier.json"
        config_file.write_text("{}")

        subdir = tmp_path / "subdir" / "deep"
        subdir.mkdir(parents=True)

        test_file = subdir / "BUILD"
        test_file.write_text("")

        result = core.find_config_dir(str(test_file))
        assert result == str(tmp_path)

    def test_no_config_found(self, tmp_path: Path) -> None:
        test_file = tmp_path / "BUILD"
        test_file.write_text("")

        result = core.find_config_dir(str(test_file))
        assert result is None

    def test_with_directory_path(self, tmp_path: Path) -> None:
        config_file = tmp_path / ".buildifier.json"
        config_file.write_text("{}")

        result = core.find_config_dir(str(tmp_path))
        assert result == str(tmp_path)

    def test_custom_config_filename(self, tmp_path: Path) -> None:
        config_file = tmp_path / "custom.json"
        config_file.write_text("{}")

        test_file = tmp_path / "BUILD"
        test_file.write_text("")

        result = core.find_config_dir(str(test_file), config_filename="custom.json")
        assert result == str(tmp_path)


# ============================================================================
# SHA256 Tests
# ============================================================================


class TestNormalizeDigest:
    """Tests for normalize_digest function."""

    def test_with_prefix(self) -> None:
        digest = "sha256:abc123def456"
        assert core.normalize_digest(digest) == "abc123def456"

    def test_without_prefix(self) -> None:
        digest = "abc123def456"
        assert core.normalize_digest(digest) == "abc123def456"

    def test_full_hash(self) -> None:
        full_hash = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert core.normalize_digest(full_hash) == expected


class TestComputeSha256:
    """Tests for compute_sha256 function."""

    def test_empty_file(self, tmp_path: Path) -> None:
        test_file = tmp_path / "empty"
        test_file.write_bytes(b"")

        # SHA256 of empty file
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert core.compute_sha256(str(test_file)) == expected

    def test_known_content(self, tmp_path: Path) -> None:
        test_file = tmp_path / "test"
        test_file.write_bytes(b"hello world")

        expected = hashlib.sha256(b"hello world").hexdigest()
        assert core.compute_sha256(str(test_file)) == expected


class TestVerifySha256:
    """Tests for verify_sha256 function."""

    def test_matching_hash(self, tmp_path: Path) -> None:
        test_file = tmp_path / "test"
        test_file.write_bytes(b"test content")

        expected = hashlib.sha256(b"test content").hexdigest()
        assert core.verify_sha256(str(test_file), expected) is True

    def test_matching_hash_with_prefix(self, tmp_path: Path) -> None:
        test_file = tmp_path / "test"
        test_file.write_bytes(b"test content")

        expected = "sha256:" + hashlib.sha256(b"test content").hexdigest()
        assert core.verify_sha256(str(test_file), expected) is True

    def test_non_matching_hash(self, tmp_path: Path) -> None:
        test_file = tmp_path / "test"
        test_file.write_bytes(b"test content")

        assert core.verify_sha256(str(test_file), "invalid_hash") is False

    def test_case_insensitive_comparison(self, tmp_path: Path) -> None:
        """SHA256 comparison should be case-insensitive."""
        test_file = tmp_path / "test"
        test_file.write_bytes(b"test content")

        expected_lower = hashlib.sha256(b"test content").hexdigest().lower()
        expected_upper = expected_lower.upper()

        assert core.verify_sha256(str(test_file), expected_lower) is True
        assert core.verify_sha256(str(test_file), expected_upper) is True


# ============================================================================
# Line Ending Tests
# ============================================================================


class TestDetectLineEnding:
    """Tests for detect_line_ending function."""

    def test_unix_style(self) -> None:
        content = "line1\nline2\nline3"
        assert core.detect_line_ending(content) == "\n"

    def test_windows_style(self) -> None:
        content = "line1\r\nline2\r\nline3"
        assert core.detect_line_ending(content) == "\r\n"

    def test_mixed_defaults_to_windows(self) -> None:
        # If CRLF is present, treat as Windows
        content = "line1\r\nline2\nline3"
        assert core.detect_line_ending(content) == "\r\n"

    def test_empty_content(self) -> None:
        assert core.detect_line_ending("") == "\n"

    def test_single_line(self) -> None:
        assert core.detect_line_ending("single line") == "\n"


class TestNormalizeLineEnding:
    """Tests for normalize_line_ending function."""

    def test_to_unix(self) -> None:
        content = "line1\r\nline2\r\n"
        result = core.normalize_line_ending(content, "\n")
        assert result == "line1\nline2\n"

    def test_to_windows(self) -> None:
        content = "line1\nline2\n"
        result = core.normalize_line_ending(content, "\r\n")
        assert result == "line1\r\nline2\r\n"

    def test_already_normalized(self) -> None:
        content = "line1\nline2\n"
        result = core.normalize_line_ending(content, "\n")
        assert result == "line1\nline2\n"

    def test_mixed_line_endings_to_unix(self) -> None:
        """Mixed line endings should be normalized."""
        content = "line1\r\nline2\nline3\r\n"
        result = core.normalize_line_ending(content, "\n")
        assert result == "line1\nline2\nline3\n"

    def test_mixed_line_endings_to_windows(self) -> None:
        """Mixed line endings should be normalized to Windows."""
        content = "line1\r\nline2\nline3\r\n"
        result = core.normalize_line_ending(content, "\r\n")
        assert result == "line1\r\nline2\r\nline3\r\n"

    def test_empty_content(self) -> None:
        assert core.normalize_line_ending("", "\n") == ""
        assert core.normalize_line_ending("", "\r\n") == ""

    def test_no_line_endings(self) -> None:
        """Single line without newline should remain unchanged."""
        assert core.normalize_line_ending("single", "\n") == "single"
        assert core.normalize_line_ending("single", "\r\n") == "single"


# ============================================================================
# Lint Output Parsing Tests
# ============================================================================


class TestLintWarning:
    """Tests for LintWarning class."""

    def test_creation(self) -> None:
        warning = core.LintWarning(
            filename="BUILD",
            line=10,
            column=5,
            category="load",
            message="Test message",
            url="http://example.com",
            actionable=True,
        )

        assert warning.filename == "BUILD"
        assert warning.line == 10
        assert warning.column == 5
        assert warning.category == "load"
        assert warning.message == "Test message"
        assert warning.url == "http://example.com"
        assert warning.actionable is True

    def test_equality(self) -> None:
        w1 = core.LintWarning("BUILD", 10, 5, "load", "msg")
        w2 = core.LintWarning("BUILD", 10, 5, "load", "msg")
        w3 = core.LintWarning("BUILD", 11, 5, "load", "msg")

        assert w1 == w2
        assert w1 != w3

    def test_repr(self) -> None:
        warning = core.LintWarning("BUILD", 10, 5, "load", "Test")
        repr_str = repr(warning)
        assert "BUILD:10:5" in repr_str
        assert "load" in repr_str

    def test_equality_with_non_warning(self) -> None:
        """Comparing with non-LintWarning should return NotImplemented."""
        warning = core.LintWarning("BUILD", 10, 5, "load", "msg")
        assert warning.__eq__("not a warning") is NotImplemented
        assert warning.__eq__(123) is NotImplemented
        assert warning.__eq__(None) is NotImplemented


class TestLintResult:
    """Tests for LintResult class."""

    def test_properties(self) -> None:
        result = core.LintResult(
            success=True,
            formatted=False,
            valid=True,
            warnings=[core.LintWarning("BUILD", 1, 1, "test", "msg")],
        )

        assert result.needs_formatting is True
        assert result.has_warnings is True
        assert result.has_errors is False

    def test_status_message_ok(self) -> None:
        result = core.LintResult(
            success=True, formatted=True, valid=True, warnings=[]
        )
        assert result.get_status_message() == "OK"

    def test_status_message_warnings(self) -> None:
        result = core.LintResult(
            success=True,
            formatted=True,
            valid=True,
            warnings=[core.LintWarning("BUILD", 1, 1, "test", "msg")],
        )
        assert "1 warning" in result.get_status_message()

    def test_status_message_needs_formatting(self) -> None:
        result = core.LintResult(
            success=True, formatted=False, valid=True, warnings=[]
        )
        assert "needs formatting" in result.get_status_message()

    def test_status_message_syntax_error(self) -> None:
        result = core.LintResult(
            success=False, formatted=False, valid=False, warnings=[]
        )
        assert "syntax error" in result.get_status_message()

    def test_status_message_multiple_warnings(self) -> None:
        result = core.LintResult(
            success=True,
            formatted=True,
            valid=True,
            warnings=[
                core.LintWarning("BUILD", 1, 1, "a", "msg1"),
                core.LintWarning("BUILD", 2, 1, "b", "msg2"),
                core.LintWarning("BUILD", 3, 1, "c", "msg3"),
            ],
        )
        assert "3 warnings" in result.get_status_message()

    def test_status_message_combined(self) -> None:
        """Test status with both warnings and needs formatting."""
        result = core.LintResult(
            success=True,
            formatted=False,
            valid=True,
            warnings=[core.LintWarning("BUILD", 1, 1, "test", "msg")],
        )
        msg = result.get_status_message()
        assert "1 warning" in msg
        assert "needs formatting" in msg


class TestParseSyntaxError:
    """Tests for parse_syntax_error function."""

    def test_standard_syntax_error(self) -> None:
        stderr = "test_error.bzl:11:1: syntax error near use_extension"
        result = core.parse_syntax_error(stderr)

        assert result is not None
        assert result.filename == "test_error.bzl"
        assert result.line == 11
        assert result.column == 1
        assert result.category == "syntax"
        assert "syntax error" in result.message
        assert "use_extension" in result.message

    def test_syntax_error_empty_near(self) -> None:
        """Syntax error with empty 'near' clause."""
        stderr = "test.bzl:5:3: syntax error near \n"
        result = core.parse_syntax_error(stderr)

        assert result is not None
        assert result.line == 5
        assert result.column == 3
        assert "syntax error" in result.message

    def test_stdin_syntax_error(self) -> None:
        stderr = "<stdin>:11:1: syntax error near "
        result = core.parse_syntax_error(stderr)

        assert result is not None
        assert result.filename == "<stdin>"
        assert result.line == 11

    def test_unexpected_newline_error(self) -> None:
        """Different error type: unexpected newline in string."""
        stderr = 'test.bzl:1:11: unexpected newline in string'
        result = core.parse_syntax_error(stderr)

        assert result is not None
        assert result.line == 1
        assert result.column == 11
        assert "unexpected newline" in result.message

    def test_syntax_error_without_near(self) -> None:
        """Syntax error without 'near' clause."""
        stderr = "test.bzl:3:1: syntax error"
        result = core.parse_syntax_error(stderr)

        assert result is not None
        assert result.line == 3
        assert result.message == "syntax error"

    def test_no_error_pattern(self) -> None:
        """Non-error messages should return None."""
        # This is a warning, not an error with location
        stderr = "warning: something"
        result = core.parse_syntax_error(stderr)

        assert result is None

    def test_empty_stderr(self) -> None:
        result = core.parse_syntax_error("")
        assert result is None

    def test_multiline_stderr(self) -> None:
        """Should find syntax error in multiline output."""
        stderr = "some warning\nBUILD:10:5: syntax error near foo\nanother line"
        result = core.parse_syntax_error(stderr)

        assert result is not None
        assert result.filename == "BUILD"
        assert result.line == 10
        assert result.column == 5

    def test_windows_path(self) -> None:
        """Windows paths with drive letters should be parsed correctly."""
        stderr = r"C:\Dev\project\BUILD:15:3: syntax error near load"
        result = core.parse_syntax_error(stderr)

        assert result is not None
        assert result.filename == r"C:\Dev\project\BUILD"
        assert result.line == 15
        assert result.column == 3

    def test_windows_path_backslash(self) -> None:
        """Windows paths with backslashes in buildifier output."""
        stderr = "C:\\Users\\test\\BUILD.bazel:7:1: unexpected token"
        result = core.parse_syntax_error(stderr)

        assert result is not None
        assert result.filename == "C:\\Users\\test\\BUILD.bazel"
        assert result.line == 7


class TestParseLintOutput:
    """Tests for parse_lint_output function."""

    @pytest.fixture
    def fixtures_dir(self) -> Path:
        return Path(__file__).parent / "fixtures"

    def test_empty_output(self, fixtures_dir: Path) -> None:
        json_str = (fixtures_dir / "lint_output_empty.json").read_text()
        result = core.parse_lint_output(json_str)

        assert result.success is True
        assert result.formatted is True
        assert result.valid is True
        assert len(result.warnings) == 0

    def test_warnings_output(self, fixtures_dir: Path) -> None:
        json_str = (fixtures_dir / "lint_output_warnings.json").read_text()
        result = core.parse_lint_output(json_str)

        assert result.success is True
        assert result.formatted is True
        assert result.valid is True
        assert len(result.warnings) == 2

        # Check first warning
        w1 = result.warnings[0]
        assert w1.line == 10
        assert w1.column == 1
        assert w1.category == "load"
        assert w1.actionable is True

        # Check second warning
        w2 = result.warnings[1]
        assert w2.line == 25
        assert w2.category == "unused-variable"

    def test_not_formatted_output(self, fixtures_dir: Path) -> None:
        json_str = (fixtures_dir / "lint_output_not_formatted.json").read_text()
        result = core.parse_lint_output(json_str)

        assert result.success is True
        assert result.formatted is False
        assert result.valid is True
        assert result.needs_formatting is True

    def test_invalid_output(self, fixtures_dir: Path) -> None:
        json_str = (fixtures_dir / "lint_output_invalid.json").read_text()
        result = core.parse_lint_output(json_str)

        assert result.success is False
        assert result.valid is False
        assert result.has_errors is True

    def test_mixed_output(self, fixtures_dir: Path) -> None:
        json_str = (fixtures_dir / "lint_output_mixed.json").read_text()
        result = core.parse_lint_output(json_str)

        assert result.formatted is False  # First file not formatted
        assert result.valid is True
        assert len(result.warnings) == 2  # One from each file

    def test_invalid_json(self) -> None:
        result = core.parse_lint_output("not valid json")

        assert result.success is False
        assert result.valid is False
        assert result.raw_output == "not valid json"

    def test_single_object_format(self) -> None:
        # Some versions might return a single object instead of array
        json_str = json.dumps(
            {
                "filename": "BUILD",
                "formatted": True,
                "valid": True,
                "success": True,
                "warnings": [],
            }
        )
        result = core.parse_lint_output(json_str)
        assert result.success is True

    def test_new_format_with_files_key(self, fixtures_dir: Path) -> None:
        """Test new buildifier format: {"success": bool, "files": [...]}"""
        json_str = (fixtures_dir / "lint_output_syntax_error.json").read_text()
        result = core.parse_lint_output(json_str)

        assert result.success is False
        assert result.formatted is False
        assert result.valid is False
        assert result.has_errors is True
        assert len(result.warnings) == 0

    def test_new_format_with_warnings(self) -> None:
        """Test new buildifier format with warnings."""
        json_str = json.dumps({
            "success": True,
            "files": [{
                "filename": "BUILD",
                "formatted": True,
                "valid": True,
                "warnings": [
                    {
                        "start": {"line": 5, "column": 1},
                        "category": "load",
                        "message": "Load statement should be at the top",
                        "url": "https://example.com/lint/load",
                        "actionable": True,
                    },
                    {
                        "start": {"line": 10, "column": 3},
                        "category": "unused-variable",
                        "message": "Variable 'x' is unused",
                        "actionable": False,
                    },
                ]
            }]
        })
        result = core.parse_lint_output(json_str)

        assert result.success is True
        assert result.valid is True
        assert len(result.warnings) == 2

        # Check first warning has all fields
        w1 = result.warnings[0]
        assert w1.line == 5
        assert w1.column == 1
        assert w1.category == "load"
        assert w1.url == "https://example.com/lint/load"
        assert w1.actionable is True

        # Check second warning
        w2 = result.warnings[1]
        assert w2.line == 10
        assert w2.actionable is False

    def test_new_format_multiple_files(self) -> None:
        """Test new format with multiple files."""
        json_str = json.dumps({
            "success": True,
            "files": [
                {
                    "filename": "BUILD",
                    "formatted": True,
                    "valid": True,
                    "warnings": [{"start": {"line": 1, "column": 1}, "category": "test", "message": "msg1"}]
                },
                {
                    "filename": "rules.bzl",
                    "formatted": False,
                    "valid": True,
                    "warnings": [{"start": {"line": 2, "column": 2}, "category": "test", "message": "msg2"}]
                },
            ]
        })
        result = core.parse_lint_output(json_str)

        assert result.success is True
        assert result.formatted is False  # One file not formatted
        assert result.valid is True
        assert len(result.warnings) == 2
        assert result.warnings[0].filename == "BUILD"
        assert result.warnings[1].filename == "rules.bzl"

    def test_warning_missing_start(self) -> None:
        """Warning without start should default to line 1, column 1."""
        json_str = json.dumps({
            "success": True,
            "files": [{
                "filename": "BUILD",
                "formatted": True,
                "valid": True,
                "warnings": [{"category": "test", "message": "missing start"}]
            }]
        })
        result = core.parse_lint_output(json_str)

        assert len(result.warnings) == 1
        assert result.warnings[0].line == 1
        assert result.warnings[0].column == 1

    def test_empty_files_array(self) -> None:
        """Empty files array should result in success with no warnings."""
        json_str = json.dumps({"success": True, "files": []})
        result = core.parse_lint_output(json_str)

        assert result.success is True
        assert result.valid is True
        assert result.formatted is True
        assert len(result.warnings) == 0

    def test_file_missing_warnings_key(self) -> None:
        """File without warnings key should be handled gracefully."""
        json_str = json.dumps({
            "success": True,
            "files": [{
                "filename": "BUILD",
                "formatted": True,
                "valid": True
                # no warnings key
            }]
        })
        result = core.parse_lint_output(json_str)

        assert result.success is True
        assert len(result.warnings) == 0

    def test_file_missing_optional_fields(self) -> None:
        """File with minimal fields should use defaults."""
        json_str = json.dumps({
            "success": True,
            "files": [{"filename": "BUILD"}]  # Only filename
        })
        result = core.parse_lint_output(json_str)

        assert result.success is True
        assert result.formatted is True  # Default
        assert result.valid is True  # Default

    def test_syntax_error_from_stderr(self) -> None:
        """Syntax error should be extracted from stderr when valid=false."""
        json_str = json.dumps({
            "success": False,
            "files": [{
                "filename": "test.bzl",
                "formatted": False,
                "valid": False,
                "warnings": []
            }]
        })
        stderr = "test.bzl:11:1: syntax error near use_extension"
        result = core.parse_lint_output(json_str, stderr)

        assert result.success is False
        assert result.valid is False
        assert len(result.warnings) == 1

        warning = result.warnings[0]
        assert warning.line == 11
        assert warning.column == 1
        assert warning.category == "syntax"
        assert "syntax error" in warning.message

    def test_no_duplicate_when_no_stderr(self) -> None:
        """Should not add warning if no stderr provided."""
        json_str = json.dumps({
            "success": False,
            "files": [{
                "filename": "test.bzl",
                "formatted": False,
                "valid": False,
                "warnings": []
            }]
        })
        result = core.parse_lint_output(json_str, "")

        assert result.valid is False
        assert len(result.warnings) == 0


# ============================================================================
# Buildifier Args Tests
# ============================================================================


class TestBuildBuildifierArgs:
    """Tests for build_buildifier_args function."""

    def test_basic_args(self) -> None:
        args = core.build_buildifier_args(mode="fix")
        assert args == ["--mode", "fix"]

    def test_with_file_type(self) -> None:
        args = core.build_buildifier_args(mode="check", file_type="build")
        assert "--type" in args
        assert "build" in args

    def test_with_lint_mode(self) -> None:
        args = core.build_buildifier_args(mode="fix", lint_mode="fix")
        assert "--lint" in args
        assert "fix" in args

    def test_with_warnings(self) -> None:
        args = core.build_buildifier_args(mode="fix", warnings="all")
        assert "--warnings" in args
        assert "all" in args

    def test_with_extra_args(self) -> None:
        args = core.build_buildifier_args(mode="fix", extra_args=["--verbose"])
        assert "--verbose" in args


class TestBuildLintCheckArgs:
    """Tests for build_lint_check_args function."""

    def test_basic_args(self) -> None:
        args = core.build_lint_check_args()
        assert "--format=json" in args
        assert "--mode=check" in args
        assert "--lint=warn" in args

    def test_with_file_type(self) -> None:
        args = core.build_lint_check_args(file_type="bzl")
        assert "--type" in args
        assert "bzl" in args

    def test_with_warnings(self) -> None:
        args = core.build_lint_check_args(warnings="-positional-args")
        assert "--warnings" in args
        assert "-positional-args" in args

    def test_with_extra_args(self) -> None:
        args = core.build_lint_check_args(extra_args=["--verbose"])
        assert "--verbose" in args


# ============================================================================
# Download URL Tests
# ============================================================================


class TestFindDownloadUrl:
    """Tests for find_download_url function."""

    def test_finds_asset(self) -> None:
        release_info = {
            "tag_name": "v7.0.0",
            "assets": [
                {
                    "name": "buildifier-darwin-arm64",
                    "browser_download_url": "https://example.com/buildifier-darwin-arm64",
                },
                {
                    "name": "buildifier-linux-amd64",
                    "browser_download_url": "https://example.com/buildifier-linux-amd64",
                },
            ],
        }

        result = core.find_download_url(release_info, "buildifier-darwin-arm64")
        assert result is not None
        url, digest = result
        assert url == "https://example.com/buildifier-darwin-arm64"

    def test_finds_asset_with_digest(self) -> None:
        """Test that digest is extracted from GitHub API asset metadata."""
        release_info = {
            "tag_name": "v8.5.1",
            "assets": [
                {
                    "name": "buildifier-windows-amd64.exe",
                    "browser_download_url": "https://github.com/bazelbuild/buildtools/releases/download/v8.5.1/buildifier-windows-amd64.exe",
                    "digest": "sha256:f4ecb9c73de2bc38b845d4ee27668f6248c4813a6647db4b4931a7556052e4e1",
                },
            ],
        }

        result = core.find_download_url(release_info, "buildifier-windows-amd64.exe")
        assert result is not None
        url, digest = result
        assert url == "https://github.com/bazelbuild/buildtools/releases/download/v8.5.1/buildifier-windows-amd64.exe"
        assert digest == "sha256:f4ecb9c73de2bc38b845d4ee27668f6248c4813a6647db4b4931a7556052e4e1"

    def test_digest_from_release_body_fallback(self) -> None:
        """Test fallback to digest in release body when not in asset metadata."""
        # SHA256 is exactly 64 hex characters
        expected_hash = "abc123def456abc123def456abc123def456abc123def456abc123def456abcd"
        release_info = {
            "tag_name": "v7.0.0",
            "body": f"Release notes\n\nbuildifier-linux-amd64 {expected_hash}\n",
            "assets": [
                {
                    "name": "buildifier-linux-amd64",
                    "browser_download_url": "https://example.com/buildifier-linux-amd64",
                },
            ],
        }

        result = core.find_download_url(release_info, "buildifier-linux-amd64")
        assert result is not None
        url, digest = result
        assert digest == expected_hash

    def test_asset_not_found(self) -> None:
        release_info = {
            "tag_name": "v7.0.0",
            "assets": [
                {
                    "name": "buildifier-linux-amd64",
                    "browser_download_url": "https://example.com/buildifier-linux-amd64",
                },
            ],
        }

        result = core.find_download_url(release_info, "buildifier-darwin-arm64")
        assert result is None

    def test_empty_assets(self) -> None:
        release_info = {"tag_name": "v7.0.0", "assets": []}
        result = core.find_download_url(release_info, "buildifier-darwin-arm64")
        assert result is None

    def test_asset_digest_takes_precedence_over_body(self) -> None:
        """Asset digest should be used even if body also contains a hash."""
        asset_digest = "sha256:aaaa" + "a" * 60
        body_hash = "bbbb" + "b" * 60
        release_info = {
            "tag_name": "v8.0.0",
            "body": f"buildifier-linux-amd64 {body_hash}",
            "assets": [
                {
                    "name": "buildifier-linux-amd64",
                    "browser_download_url": "https://example.com/buildifier-linux-amd64",
                    "digest": asset_digest,
                },
            ],
        }

        result = core.find_download_url(release_info, "buildifier-linux-amd64")
        assert result is not None
        url, digest = result
        # Asset digest should be returned, not body hash
        assert digest == asset_digest

    def test_no_digest_available(self) -> None:
        """When no digest in asset and no hash in body, digest should be None."""
        release_info = {
            "tag_name": "v7.0.0",
            "body": "Release notes without hash",
            "assets": [
                {
                    "name": "buildifier-linux-amd64",
                    "browser_download_url": "https://example.com/buildifier-linux-amd64",
                },
            ],
        }

        result = core.find_download_url(release_info, "buildifier-linux-amd64")
        assert result is not None
        url, digest = result
        assert url == "https://example.com/buildifier-linux-amd64"
        assert digest is None
