"""
Core logic for Buildifier Sublime Text plugin.

This module contains pure Python functions without any Sublime Text dependencies,
making it testable with pytest outside of Sublime Text environment.
"""

import hashlib
import json
import os
import platform
import re
import sys
from typing import Any, Dict, List, Optional, Tuple


# File type patterns for Bazel files
FILE_TYPE_PATTERNS = {
    # Exact matches (case-sensitive)
    "BUILD": "build",
    "WORKSPACE": "workspace",
    "MODULE.bazel": "module",
}

# Regex patterns for file types
FILE_TYPE_REGEX_PATTERNS = [
    (re.compile(r"^BUILD\..*$"), "build"),  # BUILD.bazel, BUILD.oss, etc.
    (re.compile(r"^WORKSPACE\..*$"), "workspace"),  # WORKSPACE.bazel, etc.
    (re.compile(r"^.*\.bzl$"), "bzl"),  # *.bzl
    (re.compile(r"^.*\.bzl\..*$"), "bzl"),  # *.bzl.oss, etc.
]


def is_bazel_file(filename: str, additional_patterns: Optional[Dict[str, str]] = None) -> bool:
    """
    Check if a file is a Bazel file that should be processed by buildifier.

    Args:
        filename: The filename (not full path) to check
        additional_patterns: Optional dict of additional patterns to file types

    Returns:
        True if the file is a Bazel file, False otherwise
    """
    return get_file_type(filename, additional_patterns) is not None


def get_file_type(filename: str, additional_patterns: Optional[Dict[str, str]] = None) -> Optional[str]:
    """
    Determine the Bazel file type for buildifier's --type flag.

    Args:
        filename: The filename (not full path) to check
        additional_patterns: Optional dict of additional patterns to file types
                           e.g., {"*.star": "default", "DEPS": "build"}

    Returns:
        File type string ("build", "workspace", "bzl", "module", "default") or None
    """
    basename = os.path.basename(filename)

    # Check exact matches first
    if basename in FILE_TYPE_PATTERNS:
        return FILE_TYPE_PATTERNS[basename]

    # Check regex patterns
    for pattern, file_type in FILE_TYPE_REGEX_PATTERNS:
        if pattern.match(basename):
            return file_type

    # Check additional patterns
    if additional_patterns:
        for pattern, file_type in additional_patterns.items():
            if _match_glob_pattern(basename, pattern):
                return file_type

    return None


def _match_glob_pattern(filename: str, pattern: str) -> bool:
    """
    Match a filename against a simple glob pattern.

    Supports:
        - * for any sequence of characters
        - Exact match

    Args:
        filename: The filename to match
        pattern: The glob pattern (e.g., "*.star", "DEPS")

    Returns:
        True if the pattern matches, False otherwise
    """
    if "*" not in pattern:
        return filename == pattern

    # Convert glob to regex
    regex_pattern = "^" + re.escape(pattern).replace(r"\*", ".*") + "$"
    return bool(re.match(regex_pattern, filename))


def get_platform_info() -> Tuple[str, str]:
    """
    Get the current platform information for buildifier asset selection.

    Returns:
        Tuple of (os_name, arch) where:
            os_name: "darwin", "linux", or "windows"
            arch: "amd64" or "arm64"

    Raises:
        ValueError: If the platform is not supported
    """
    system = sys.platform
    machine = platform.machine()

    # Determine OS
    if system == "darwin":
        os_name = "darwin"
    elif system.startswith("linux"):
        os_name = "linux"
    elif system == "win32":
        os_name = "windows"
    else:
        raise ValueError(f"Unsupported platform: {system}")

    # Determine architecture
    machine_lower = machine.lower()
    if machine_lower in ("x86_64", "amd64"):
        arch = "amd64"
    elif machine_lower in ("arm64", "aarch64"):
        arch = "arm64"
    else:
        raise ValueError(f"Unsupported architecture: {machine}")

    return os_name, arch


def get_asset_name(os_name: str, arch: str) -> str:
    """
    Get the buildifier asset filename for the given platform.

    Args:
        os_name: Operating system ("darwin", "linux", "windows")
        arch: Architecture ("amd64", "arm64")

    Returns:
        Asset filename (e.g., "buildifier-darwin-arm64", "buildifier-windows-amd64.exe")
    """
    name = f"buildifier-{os_name}-{arch}"
    if os_name == "windows":
        name += ".exe"
    return name


def find_config_dir(start_path: str, config_filename: str = ".buildifier.json") -> Optional[str]:
    """
    Search for a buildifier config file by walking up the directory tree.

    Args:
        start_path: Starting directory or file path
        config_filename: Name of the config file to search for

    Returns:
        Directory containing the config file, or None if not found
    """
    if os.path.isfile(start_path):
        current = os.path.dirname(start_path)
    else:
        current = start_path

    current = os.path.abspath(current)

    while True:
        config_path = os.path.join(current, config_filename)
        if os.path.isfile(config_path):
            return current

        parent = os.path.dirname(current)
        if parent == current:
            # Reached filesystem root
            return None
        current = parent


def find_download_url(release_info: Dict[str, Any], asset_name: str) -> Optional[Tuple[str, Optional[str]]]:
    """
    Find the download URL and digest for a specific asset in GitHub release info.

    Args:
        release_info: GitHub API response for a release
        asset_name: The asset filename to find

    Returns:
        Tuple of (download_url, digest) or None if not found.
        Digest may be None if not available.
    """
    assets = release_info.get("assets", [])

    download_url = None
    digest = None

    for asset in assets:
        name = asset.get("name", "")
        if name == asset_name:
            download_url = asset.get("browser_download_url")
            # GitHub API includes digest in asset metadata (format: "sha256:<hex>")
            digest = asset.get("digest")
            break

    # Fallback: check if release body contains digest info
    if download_url and not digest:
        body = release_info.get("body", "")
        # Look for sha256 hash pattern in release notes
        sha256_pattern = re.compile(rf"{re.escape(asset_name)}\s+([a-fA-F0-9]{{64}})")
        match = sha256_pattern.search(body)
        if match:
            digest = match.group(1)

    if download_url:
        return download_url, digest
    return None


def normalize_digest(digest: str) -> str:
    """
    Normalize a SHA256 digest by removing the 'sha256:' prefix if present.

    Args:
        digest: Digest string, possibly with 'sha256:' prefix

    Returns:
        Hex digest without prefix
    """
    if digest.startswith("sha256:"):
        return digest[7:]
    return digest


def compute_sha256(file_path: str) -> str:
    """
    Compute the SHA256 hash of a file.

    Args:
        file_path: Path to the file

    Returns:
        Lowercase hex digest
    """
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def verify_sha256(file_path: str, expected: str) -> bool:
    """
    Verify that a file matches the expected SHA256 hash.

    Args:
        file_path: Path to the file
        expected: Expected SHA256 digest (with or without 'sha256:' prefix)

    Returns:
        True if the hash matches, False otherwise
    """
    expected_normalized = normalize_digest(expected).lower()
    actual = compute_sha256(file_path).lower()
    return actual == expected_normalized


def detect_line_ending(content: str) -> str:
    """
    Detect the line ending style used in content.

    Args:
        content: Text content to analyze

    Returns:
        Line ending string: '\\r\\n' for Windows, '\\n' for Unix
    """
    if "\r\n" in content:
        return "\r\n"
    return "\n"


def normalize_line_ending(content: str, line_ending: str) -> str:
    """
    Normalize content to use a specific line ending style.

    Args:
        content: Text content to normalize
        line_ending: Target line ending ('\\r\\n' or '\\n')

    Returns:
        Content with normalized line endings
    """
    # First normalize to \n, then convert to target
    normalized = content.replace("\r\n", "\n")
    if line_ending == "\r\n":
        normalized = normalized.replace("\n", "\r\n")
    return normalized


class LintWarning:
    """Represents a single lint warning from buildifier."""

    def __init__(
        self,
        filename: str,
        line: int,
        column: int,
        category: str,
        message: str,
        url: Optional[str] = None,
        actionable: bool = False,
    ):
        self.filename = filename
        self.line = line
        self.column = column
        self.category = category
        self.message = message
        self.url = url
        self.actionable = actionable

    def __repr__(self) -> str:
        return f"LintWarning({self.filename}:{self.line}:{self.column} [{self.category}] {self.message})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, LintWarning):
            return NotImplemented
        return (
            self.filename == other.filename
            and self.line == other.line
            and self.column == other.column
            and self.category == other.category
            and self.message == other.message
        )


class LintResult:
    """Result of parsing buildifier lint output."""

    def __init__(
        self,
        success: bool,
        formatted: bool,
        valid: bool,
        warnings: List[LintWarning],
        raw_output: Optional[str] = None,
    ):
        self.success = success
        self.formatted = formatted
        self.valid = valid
        self.warnings = warnings
        self.raw_output = raw_output

    @property
    def needs_formatting(self) -> bool:
        """Check if the file needs formatting."""
        return not self.formatted

    @property
    def has_warnings(self) -> bool:
        """Check if there are any warnings."""
        return len(self.warnings) > 0

    @property
    def has_errors(self) -> bool:
        """Check if there are syntax errors."""
        return not self.valid

    def get_status_message(self) -> str:
        """Get a summary message for the status bar."""
        parts = []

        if not self.valid:
            parts.append("syntax error")
        elif self.warnings:
            parts.append(f"{len(self.warnings)} warning{'s' if len(self.warnings) != 1 else ''}")

        if not self.formatted:
            parts.append("needs formatting")

        if not parts:
            return "OK"

        return ", ".join(parts)


def parse_syntax_error(stderr: str) -> Optional[LintWarning]:
    """
    Parse syntax error from buildifier stderr output.

    Buildifier outputs errors to stderr in various formats:
        <filename>:<line>:<column>: syntax error near <token>
        <filename>:<line>:<column>: syntax error
        <filename>:<line>:<column>: unexpected newline in string

    Args:
        stderr: Stderr output from buildifier

    Returns:
        LintWarning if a syntax error was found, None otherwise
    """
    # Pattern: filename:line:column: error message
    # Windows paths like C:\path\file.bzl contain colons, so we can't use [^:]
    # Instead, match everything up to :digits:digits: pattern
    # (.+?) - non-greedy match for filename (including drive letter on Windows)
    # :(\d+):(\d+): - line and column numbers
    # \s*([^\n]+) - error message
    pattern = re.compile(r"(?:^|\n)(.+?):(\d+):(\d+):\s*([^\n]+)")
    match = pattern.search(stderr)

    if match:
        filename = match.group(1)
        line = int(match.group(2))
        column = int(match.group(3))
        message = match.group(4).strip()

        return LintWarning(
            filename=filename,
            line=line,
            column=column,
            category="syntax",
            message=message or "syntax error",
            actionable=False,
        )

    return None


def parse_lint_output(json_str: str, stderr: str = "") -> LintResult:
    """
    Parse buildifier JSON output from --format=json --mode=check.

    Args:
        json_str: JSON string from buildifier

    Returns:
        LintResult with parsed information
    """
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError:
        # Invalid JSON - treat as error
        return LintResult(
            success=False,
            formatted=True,
            valid=False,
            warnings=[],
            raw_output=json_str,
        )

    # Handle different output formats:
    # 1. New format: {"success": bool, "files": [...]}
    # 2. Array format: [{...}, {...}]
    # 3. Single object format: {...}
    wrapper_success = True
    if isinstance(data, dict) and "files" in data:
        files = data.get("files", [])
        wrapper_success = data.get("success", True)
    elif isinstance(data, list):
        files = data
    else:
        files = [data]

    all_warnings: List[LintWarning] = []
    overall_success = wrapper_success
    overall_formatted = True
    overall_valid = True

    for file_data in files:
        filename = file_data.get("filename", "<stdin>")
        formatted = file_data.get("formatted", True)
        valid = file_data.get("valid", True)
        success = file_data.get("success", True)

        if not success:
            overall_success = False
        if not formatted:
            overall_formatted = False
        if not valid:
            overall_valid = False
            # Try to extract syntax error from stderr
            if stderr:
                syntax_error = parse_syntax_error(stderr)
                if syntax_error:
                    all_warnings.append(syntax_error)

        warnings = file_data.get("warnings", [])
        for warning in warnings:
            start = warning.get("start", {})
            line = start.get("line", 1)
            column = start.get("column", 1)
            category = warning.get("category", "unknown")
            message = warning.get("message", "")
            url = warning.get("url")
            actionable = warning.get("actionable", False)

            all_warnings.append(
                LintWarning(
                    filename=filename,
                    line=line,
                    column=column,
                    category=category,
                    message=message,
                    url=url,
                    actionable=actionable,
                )
            )

    return LintResult(
        success=overall_success,
        formatted=overall_formatted,
        valid=overall_valid,
        warnings=all_warnings,
        raw_output=json_str,
    )


def build_buildifier_args(
    mode: str,
    file_type: Optional[str] = None,
    lint_mode: Optional[str] = None,
    warnings: Optional[str] = None,
    extra_args: Optional[List[str]] = None,
) -> List[str]:
    """
    Build command-line arguments for buildifier.

    Args:
        mode: Buildifier mode ("fix", "check", "diff")
        file_type: File type for --type flag (required for stdin)
        lint_mode: Lint mode ("off", "warn", "fix")
        warnings: Warning categories string (e.g., "all", "-positional-args")
        extra_args: Additional arguments to pass

    Returns:
        List of command-line arguments
    """
    args = []

    args.extend(["--mode", mode])

    if file_type:
        args.extend(["--type", file_type])

    if lint_mode:
        args.extend(["--lint", lint_mode])

    if warnings:
        args.extend(["--warnings", warnings])

    if extra_args:
        args.extend(extra_args)

    return args


def build_lint_check_args(
    file_type: Optional[str] = None,
    warnings: Optional[str] = None,
    extra_args: Optional[List[str]] = None,
) -> List[str]:
    """
    Build arguments for lint check (JSON output).

    Args:
        file_type: File type for --type flag
        warnings: Warning categories string
        extra_args: Additional arguments

    Returns:
        List of command-line arguments for lint checking
    """
    args = ["--format=json", "--mode=check"]

    if file_type:
        args.extend(["--type", file_type])

    args.extend(["--lint=warn"])

    if warnings:
        args.extend(["--warnings", warnings])

    if extra_args:
        args.extend(extra_args)

    return args
