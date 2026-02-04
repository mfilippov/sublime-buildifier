"""
Buildifier plugin for Sublime Text.

This module provides commands and event listeners for formatting and linting
Bazel files using buildifier.
"""

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple

import sublime
import sublime_plugin

from . import buildifier_core as core

# Guard flag to prevent save loops
_save_guard: Dict[int, bool] = {}


def plugin_loaded() -> None:
    """Called when the plugin is loaded."""
    # Ensure cache directory exists
    cache_dir = get_cache_dir()
    os.makedirs(cache_dir, exist_ok=True)


def get_settings() -> sublime.Settings:
    """Get plugin settings."""
    return sublime.load_settings("Buildifier.sublime-settings")


def get_cache_dir() -> str:
    """Get the cache directory for storing downloaded buildifier."""
    return os.path.join(sublime.cache_path(), "Buildifier")


def get_buildifier_path() -> Optional[str]:
    """
    Get the path to buildifier executable.

    Returns the configured path, or the cached download path if available.
    """
    settings = get_settings()
    configured_path = settings.get("buildifier_path")

    if configured_path:
        # Expand ~ and environment variables (e.g., ~/bin/buildifier, %USERPROFILE%\bin)
        expanded_path = os.path.expandvars(os.path.expanduser(configured_path))
        if os.path.isfile(expanded_path):
            return expanded_path
        # Check if it's in PATH
        path_result = shutil.which(expanded_path)
        if path_result:
            return path_result
        return None

    # Check for downloaded buildifier
    try:
        os_name, arch = core.get_platform_info()
        asset_name = core.get_asset_name(os_name, arch)
        cached_path = os.path.join(get_cache_dir(), asset_name)
        if os.path.isfile(cached_path):
            return cached_path
    except ValueError:
        pass

    # Check if buildifier is in PATH
    path_result = shutil.which("buildifier")
    if path_result:
        return path_result

    # Check common installation locations
    home = os.path.expanduser("~")
    common_paths = [
        os.path.join(home, "go", "bin", "buildifier"),
        os.path.join(home, ".local", "bin", "buildifier"),
        "/usr/local/bin/buildifier",
        "/opt/homebrew/bin/buildifier",
    ]
    for path in common_paths:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path

    return None


def get_working_dir(view: sublime.View) -> str:
    """
    Determine the working directory for running buildifier.

    Based on the working_dir_mode setting.
    """
    settings = get_settings()
    mode = settings.get("working_dir_mode", "config_dir")
    file_path = view.file_name()

    if mode == "custom":
        custom_dir = settings.get("custom_working_dir")
        if custom_dir and os.path.isdir(custom_dir):
            return custom_dir

    if mode == "file_dir" and file_path:
        return os.path.dirname(file_path)

    if mode == "project_root":
        folders = view.window().folders() if view.window() else []
        if folders:
            return folders[0]
        if file_path:
            return os.path.dirname(file_path)
        return os.getcwd()

    # config_dir mode (default)
    if file_path:
        config_dir = core.find_config_dir(file_path)
        if config_dir:
            return config_dir

    # Fallback: project root, then file dir, then cwd
    if view.window():
        folders = view.window().folders()
        if folders:
            return folders[0]

    if file_path:
        return os.path.dirname(file_path)

    return os.getcwd()


def get_file_type(view: sublime.View) -> Optional[str]:
    """Get the buildifier file type for the current view."""
    file_name = view.file_name()
    if file_name:
        basename = os.path.basename(file_name)
    else:
        # Try to get from view name or default
        basename = view.name() or ""

    settings = get_settings()
    additional_patterns = settings.get("additional_file_patterns", {})

    return core.get_file_type(basename, additional_patterns)


def is_bazel_file(view: sublime.View) -> bool:
    """Check if the current view is a Bazel file."""
    return get_file_type(view) is not None


def ensure_buildifier(window: Optional[sublime.Window] = None) -> bool:
    """
    Ensure buildifier is available, downloading if necessary.

    Returns True if buildifier is available, False otherwise.
    """
    if get_buildifier_path():
        return True

    settings = get_settings()
    if not settings.get("auto_download", True):
        sublime.error_message("Buildifier not found. Please install it or enable auto_download.")
        return False

    # Auto-download buildifier
    sublime.status_message("Buildifier: Downloading...")
    if window:
        window.run_command("buildifier_download")
    else:
        sublime.run_command("buildifier_download")

    return False  # Download is async, so return False for now


def run_buildifier(
    args: List[str],
    stdin_content: Optional[str] = None,
    cwd: Optional[str] = None,
    timeout_ms: Optional[int] = None,
) -> Tuple[int, str, str]:
    """
    Run buildifier with the given arguments.

    Args:
        args: Command-line arguments
        stdin_content: Optional content to pass via stdin
        cwd: Working directory
        timeout_ms: Timeout in milliseconds

    Returns:
        Tuple of (return_code, stdout, stderr)
    """
    buildifier_path = get_buildifier_path()
    if not buildifier_path:
        return -1, "", "buildifier not found"

    settings = get_settings()
    extra_args = settings.get("buildifier_args", [])

    cmd = [buildifier_path] + args + extra_args

    timeout_sec = (timeout_ms or settings.get("buildifier_timeout", 5000)) / 1000.0

    try:
        # On Windows, hide the console window that would otherwise flash
        creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE if stdin_content is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            creationflags=creationflags,
        )

        input_bytes = stdin_content.encode("utf-8") if stdin_content is not None else None
        stdout, stderr = process.communicate(input=input_bytes, timeout=timeout_sec)

        return process.returncode, stdout.decode("utf-8"), stderr.decode("utf-8")

    except subprocess.TimeoutExpired:
        process.kill()
        return -1, "", "buildifier timed out"
    except FileNotFoundError:
        return -1, "", f"buildifier not found at: {buildifier_path}"
    except Exception as e:
        return -1, "", str(e)


def format_content(view: sublime.View, content: str) -> Optional[str]:
    """
    Format content using buildifier.

    Args:
        view: The Sublime Text view
        content: Content to format

    Returns:
        Formatted content or None on error
    """
    file_type = get_file_type(view)
    cwd = get_working_dir(view)

    args = core.build_buildifier_args(mode="fix", file_type=file_type)

    # Detect and preserve line ending
    original_ending = core.detect_line_ending(content)

    returncode, stdout, stderr = run_buildifier(args, stdin_content=content, cwd=cwd)

    if returncode != 0:
        # Don't show modal dialog for syntax errors - just show status message
        # Caller can run lint to highlight the error location
        if stderr:
            # Extract short error message for status bar
            first_line = stderr.strip().split('\n')[0]
            sublime.status_message(f"Buildifier: {first_line}")
        return None

    # Restore original line ending style
    formatted = core.normalize_line_ending(stdout, original_ending)
    return formatted


def lint_content(view: sublime.View, content: str) -> Optional[core.LintResult]:
    """
    Lint content using buildifier.

    Args:
        view: The Sublime Text view
        content: Content to lint

    Returns:
        LintResult or None on error
    """
    file_type = get_file_type(view)
    cwd = get_working_dir(view)
    settings = get_settings()
    warnings = settings.get("warnings")

    args = core.build_lint_check_args(file_type=file_type, warnings=warnings)

    returncode, stdout, stderr = run_buildifier(args, stdin_content=content, cwd=cwd)

    # With --format=json, buildifier returns 0 even when there are issues
    # Parse the JSON output to get the actual result
    # Pass stderr to extract syntax error location if present
    if stdout:
        return core.parse_lint_output(stdout, stderr)

    if stderr:
        sublime.status_message(f"Buildifier: {stderr}")
        return None

    return None


def show_warnings_in_panel(view: sublime.View, result: core.LintResult) -> None:
    """Display lint warnings in an output panel."""
    window = view.window()
    if not window:
        return

    settings = get_settings()
    if not settings.get("show_warnings_in_panel", True):
        return

    panel = window.create_output_panel("buildifier")
    panel.set_read_only(False)

    cwd = get_working_dir(view)
    lines = [f"Buildifier Warnings (cwd: {cwd}):\n"]

    if not result.valid:
        lines.append("  Syntax error in file\n")

    for warning in result.warnings:
        actionable_marker = " [fixable]" if warning.actionable else ""
        lines.append(
            f"  {warning.filename}:{warning.line}:{warning.column} "
            f"[{warning.category}]{actionable_marker} {warning.message}\n"
        )
        if warning.url:
            lines.append(f"    -> {warning.url}\n")

    if not result.formatted:
        lines.append("\n  File needs formatting.\n")

    if not result.warnings and result.valid and result.formatted:
        lines.append("  No issues found.\n")

    panel.run_command("append", {"characters": "".join(lines)})
    panel.set_read_only(True)

    window.run_command("show_panel", {"panel": "output.buildifier"})


def highlight_warnings(view: sublime.View, result: core.LintResult) -> None:
    """Add region highlights for warnings in the editor."""
    settings = get_settings()
    if not settings.get("highlight_warnings_in_editor", True):
        return

    warning_regions = []
    error_regions = []
    annotations = []
    annotation_regions = []

    for warning in result.warnings:
        # Convert 1-based line/column to 0-based
        point = view.text_point(warning.line - 1, warning.column - 1)
        # Highlight the word at the position
        word_region = view.word(point)
        if word_region.empty():
            # If no word, highlight a small region
            word_region = sublime.Region(point, point + 1)
        warning_regions.append(word_region)

        # Add annotation with error message
        annotation_regions.append(word_region)
        annotations.append(warning.message)

    warning_scope = settings.get("warning_scope", "markup.warning")
    error_scope = settings.get("error_scope", "markup.error")

    # Get annotation color from theme scope or settings
    annotation_color = settings.get("annotation_color")
    if not annotation_color:
        # Try common error scopes in order of preference
        for scope in ["invalid.illegal", "invalid", error_scope, "message.error"]:
            style = view.style_for_scope(scope)
            if style.get("foreground"):
                annotation_color = style["foreground"]
                break
        else:
            annotation_color = "#FF0000"  # Fallback

    view.add_regions(
        key="buildifier.warnings",
        regions=warning_regions,
        scope=warning_scope,
        icon="dot",
        flags=sublime.DRAW_SQUIGGLY_UNDERLINE | sublime.DRAW_NO_FILL | sublime.DRAW_NO_OUTLINE,
        annotations=annotations,
        annotation_color=annotation_color,
    )

    # Add error regions for syntax errors (from parsed warnings with category "syntax")
    # Only add end-of-file marker if we have no warning locations
    if not result.valid and not result.warnings:
        # Fallback: add error indicator at end of file if no location available
        error_regions.append(sublime.Region(view.size() - 1, view.size()))

    # Always update error regions (clears stale markers when file becomes valid)
    view.add_regions(
        key="buildifier.errors",
        regions=error_regions,
        scope=error_scope,
        icon="circle",
        flags=sublime.DRAW_NO_FILL,
    )


def clear_highlights(view: sublime.View) -> None:
    """Clear all buildifier highlights from the view."""
    view.erase_regions("buildifier.warnings")
    view.erase_regions("buildifier.errors")


def update_status_bar(view: sublime.View, result: Optional[core.LintResult]) -> None:
    """Update the status bar with lint result."""
    if result:
        status = f"Buildifier: {result.get_status_message()}"
    else:
        status = ""
    view.set_status("buildifier", status)


class BuildifierFormatCommand(sublime_plugin.TextCommand):
    """Format the current file with buildifier."""

    def run(self, edit: sublime.Edit) -> None:
        if not is_bazel_file(self.view):
            sublime.status_message("Buildifier: Not a Bazel file")
            return

        if not get_buildifier_path():
            ensure_buildifier(self.view.window())
            return

        content = self.view.substr(sublime.Region(0, self.view.size()))
        formatted = format_content(self.view, content)

        if formatted is not None and formatted != content:
            # Replace the entire content
            self.view.replace(edit, sublime.Region(0, self.view.size()), formatted)
            sublime.status_message("Buildifier: Formatted")
        elif formatted == content:
            sublime.status_message("Buildifier: Already formatted")
        else:
            # Format failed (syntax error) - run lint to highlight error location
            result = lint_content(self.view, content)
            if result:
                highlight_warnings(self.view, result)
                update_status_bar(self.view, result)

    def is_enabled(self) -> bool:
        return is_bazel_file(self.view)


class BuildifierLintCommand(sublime_plugin.TextCommand):
    """Lint the current file with buildifier and show warnings."""

    def run(self, edit: sublime.Edit) -> None:
        if not is_bazel_file(self.view):
            sublime.status_message("Buildifier: Not a Bazel file")
            return

        if not get_buildifier_path():
            ensure_buildifier(self.view.window())
            return

        content = self.view.substr(sublime.Region(0, self.view.size()))
        result = lint_content(self.view, content)

        if result:
            show_warnings_in_panel(self.view, result)
            highlight_warnings(self.view, result)
            update_status_bar(self.view, result)

    def is_enabled(self) -> bool:
        return is_bazel_file(self.view)


class BuildifierFormatAndFixCommand(sublime_plugin.TextCommand):
    """Format the current file and apply lint fixes."""

    def run(self, edit: sublime.Edit) -> None:
        if not is_bazel_file(self.view):
            sublime.status_message("Buildifier: Not a Bazel file")
            return

        if not get_buildifier_path():
            ensure_buildifier(self.view.window())
            return

        file_type = get_file_type(self.view)
        cwd = get_working_dir(self.view)
        settings = get_settings()
        warnings = settings.get("warnings")

        content = self.view.substr(sublime.Region(0, self.view.size()))
        original_ending = core.detect_line_ending(content)

        args = core.build_buildifier_args(
            mode="fix", file_type=file_type, lint_mode="fix", warnings=warnings
        )

        returncode, stdout, stderr = run_buildifier(args, stdin_content=content, cwd=cwd)

        if returncode != 0:
            if stderr:
                sublime.error_message(f"Buildifier error:\n{stderr}")
            return

        formatted = core.normalize_line_ending(stdout, original_ending)

        if formatted != content:
            self.view.replace(edit, sublime.Region(0, self.view.size()), formatted)
            sublime.status_message("Buildifier: Formatted and fixed")
        else:
            sublime.status_message("Buildifier: No changes needed")

    def is_enabled(self) -> bool:
        return is_bazel_file(self.view)


class BuildifierJumpToWarningCommand(sublime_plugin.TextCommand):
    """Jump to the next warning in the file."""

    def run(self, edit: sublime.Edit, direction: str = "next") -> None:
        if not is_bazel_file(self.view):
            sublime.status_message("Buildifier: Not a Bazel file")
            return

        if not get_buildifier_path():
            ensure_buildifier(self.view.window())
            return

        content = self.view.substr(sublime.Region(0, self.view.size()))
        result = lint_content(self.view, content)

        if not result or not result.warnings:
            sublime.status_message("Buildifier: No warnings")
            return

        # Get current cursor position
        cursor = self.view.sel()[0].begin() if self.view.sel() else 0
        cursor_row, _ = self.view.rowcol(cursor)

        # Sort warnings by line
        warnings = sorted(result.warnings, key=lambda w: (w.line, w.column))

        # Find next/previous warning
        target = None
        if direction == "next":
            # Find first warning after cursor
            for w in warnings:
                if w.line - 1 > cursor_row:
                    target = w
                    break
            # Wrap around to first warning
            if not target:
                target = warnings[0]
        else:  # previous
            # Find last warning before cursor
            for w in reversed(warnings):
                if w.line - 1 < cursor_row:
                    target = w
                    break
            # Wrap around to last warning
            if not target:
                target = warnings[-1]

        # Jump to warning
        point = self.view.text_point(target.line - 1, target.column - 1)
        self.view.sel().clear()
        self.view.sel().add(sublime.Region(point, point))
        self.view.show_at_center(point)

        # Show warning message in status bar
        sublime.status_message(f"Buildifier: [{target.category}] {target.message}")

    def is_enabled(self) -> bool:
        return is_bazel_file(self.view)


class BuildifierDownloadCommand(sublime_plugin.WindowCommand):
    """Download or update buildifier."""

    def run(self) -> None:
        # Run in background thread
        thread = threading.Thread(target=self._download)
        thread.start()

    def _download(self) -> None:
        def status(msg: str) -> None:
            sublime.set_timeout(lambda: sublime.status_message(msg), 0)

        def error(msg: str) -> None:
            sublime.set_timeout(lambda: sublime.error_message(msg), 0)

        try:
            os_name, arch = core.get_platform_info()
        except ValueError as e:
            error(f"Buildifier: {e}")
            return

        asset_name = core.get_asset_name(os_name, arch)
        cache_dir = get_cache_dir()
        target_path = os.path.join(cache_dir, asset_name)

        status("Buildifier: Fetching release info...")

        try:
            # Fetch latest release info from GitHub
            api_url = "https://api.github.com/repos/bazelbuild/buildtools/releases/latest"
            request = urllib.request.Request(
                api_url,
                headers={
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": "SublimeBuildifier",
                },
            )
            with urllib.request.urlopen(request, timeout=30) as response:
                release_info = sublime.decode_value(response.read().decode("utf-8"))

            # Find download URL
            result = core.find_download_url(release_info, asset_name)
            if not result:
                error(f"Buildifier: Asset {asset_name} not found in release")
                return

            download_url, digest = result
            tag_name = release_info.get("tag_name", "unknown")

            status(f"Buildifier: Downloading {tag_name}...")

            # Download to temporary file
            with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                tmp_path = tmp_file.name
                request = urllib.request.Request(
                    download_url, headers={"User-Agent": "SublimeBuildifier"}
                )
                with urllib.request.urlopen(request, timeout=120) as response:
                    tmp_file.write(response.read())

            # Verify SHA256 if enabled
            settings = get_settings()
            if settings.get("verify_sha256", True):
                if digest:
                    # Verify using digest from GitHub API
                    if not core.verify_sha256(tmp_path, digest):
                        os.unlink(tmp_path)
                        error("Buildifier: SHA256 verification failed!")
                        return
                else:
                    # No digest available - abort if verification is required
                    os.unlink(tmp_path)
                    error(
                        "Buildifier: SHA256 verification is enabled but no checksum available. "
                        "Download aborted. Disable verify_sha256 in settings to skip verification."
                    )
                    return

            # Move to cache directory
            os.makedirs(cache_dir, exist_ok=True)
            # Remove existing file first (required on Windows where rename fails if dest exists)
            if os.path.exists(target_path):
                os.remove(target_path)
            shutil.move(tmp_path, target_path)

            # Make executable on Unix
            if os_name != "windows":
                st = os.stat(target_path)
                os.chmod(target_path, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

            status(f"Buildifier: Downloaded {tag_name}")

        except urllib.error.URLError as e:
            error(f"Buildifier: Download failed - {e}")
        except Exception as e:
            error(f"Buildifier: {e}")


class BuildifierShowInfoCommand(sublime_plugin.TextCommand):
    """Show debug information about buildifier configuration."""

    def run(self, edit: sublime.Edit) -> None:
        window = self.view.window()
        if not window:
            return

        panel = window.create_output_panel("buildifier_info")
        panel.set_read_only(False)

        lines = ["Buildifier Info\n", "=" * 40 + "\n\n"]

        # Buildifier path
        buildifier_path = get_buildifier_path()
        lines.append(f"Buildifier path: {buildifier_path or 'Not found'}\n")

        # Version
        if buildifier_path:
            returncode, stdout, stderr = run_buildifier(["--version"])
            if returncode == 0:
                lines.append(f"Version: {stdout.strip()}\n")

        lines.append("\n")

        # Current file info
        file_path = self.view.file_name()
        lines.append(f"Current file: {file_path or 'Untitled'}\n")

        if file_path:
            file_type = get_file_type(self.view)
            lines.append(f"File type: {file_type or 'Unknown'}\n")

            cwd = get_working_dir(self.view)
            lines.append(f"Working directory: {cwd}\n")

            config_dir = core.find_config_dir(file_path)
            lines.append(f"Config directory: {config_dir or 'Not found'}\n")

        lines.append("\n")

        # Settings
        settings = get_settings()
        lines.append("Settings:\n")
        lines.append(f"  on_save: {settings.get('on_save', 'format')}\n")
        lines.append(f"  format_on_save_strategy: {settings.get('format_on_save_strategy', 'pre_save_blocking')}\n")
        lines.append(f"  working_dir_mode: {settings.get('working_dir_mode', 'config_dir')}\n")
        lines.append(f"  warnings: {settings.get('warnings')}\n")
        lines.append(f"  auto_download: {settings.get('auto_download', True)}\n")
        lines.append(f"  verify_sha256: {settings.get('verify_sha256', True)}\n")

        lines.append("\n")

        # Platform info
        try:
            os_name, arch = core.get_platform_info()
            lines.append(f"Platform: {os_name}-{arch}\n")
            lines.append(f"Asset name: {core.get_asset_name(os_name, arch)}\n")
        except ValueError as e:
            lines.append(f"Platform: Error - {e}\n")

        panel.run_command("append", {"characters": "".join(lines)})
        panel.set_read_only(True)

        window.run_command("show_panel", {"panel": "output.buildifier_info"})


class BuildifierEventListener(sublime_plugin.EventListener):
    """Event listener for format-on-save and other events."""

    def on_pre_save(self, view: sublime.View) -> None:
        """Handle pre-save event for blocking format-on-save."""
        if not is_bazel_file(view):
            return

        # Skip if buildifier not available (will be downloaded on file load)
        if not get_buildifier_path():
            return

        settings = get_settings()
        on_save = settings.get("on_save", "format")
        strategy = settings.get("format_on_save_strategy", "pre_save_blocking")

        if on_save not in ("format", "format+lint"):
            return

        if strategy != "pre_save_blocking":
            return

        # Skip if we're in a save guard (re-save from post_save)
        view_id = view.id()
        if _save_guard.get(view_id):
            return

        content = view.substr(sublime.Region(0, view.size()))
        formatted = format_content(view, content)

        if formatted is not None and formatted != content:
            view.run_command("buildifier_replace_content", {"content": formatted})

    def on_post_save_async(self, view: sublime.View) -> None:
        """Handle post-save event for async format-on-save and linting."""
        if not is_bazel_file(view):
            return

        # Skip if buildifier not available
        if not get_buildifier_path():
            return

        settings = get_settings()
        on_save = settings.get("on_save", "format")
        strategy = settings.get("format_on_save_strategy", "pre_save_blocking")

        view_id = view.id()

        # Handle post_save_resave strategy
        if on_save in ("format", "format+lint") and strategy == "post_save_resave":
            if _save_guard.get(view_id):
                # Clear guard and fall through to linting if enabled
                _save_guard[view_id] = False
            else:
                # Capture change_count to detect edits during formatting
                change_count = view.change_count()
                content = view.substr(sublime.Region(0, view.size()))
                formatted = format_content(view, content)

                if formatted is not None and formatted != content:
                    _save_guard[view_id] = True
                    # Schedule UI operations on main thread
                    sublime.set_timeout(
                        lambda: self._apply_format_and_save(view, formatted, change_count), 0
                    )
                    return

        # Handle linting
        if on_save in ("lint", "format+lint"):
            content = view.substr(sublime.Region(0, view.size()))
            result = lint_content(view, content)

            if result:
                # Schedule UI operations on main thread
                sublime.set_timeout(
                    lambda: self._apply_lint_results(view, result), 0
                )
        elif on_save == "format":
            # For format-only mode, still run lint to highlight syntax errors
            # but don't show the panel. Always update highlights to clear stale markers.
            content = view.substr(sublime.Region(0, view.size()))
            result = lint_content(view, content)

            if result:
                sublime.set_timeout(
                    lambda: self._apply_error_highlights(view, result), 0
                )

    def _apply_format_and_save(
        self, view: sublime.View, formatted: str, original_change_count: int
    ) -> None:
        """Apply formatting and save on main thread."""
        # Abort if buffer was modified during formatting to avoid overwriting edits
        if view.change_count() != original_change_count:
            _save_guard[view.id()] = False
            sublime.status_message("Buildifier: Skipped format (buffer modified)")
            return
        view.run_command("buildifier_replace_content", {"content": formatted})
        view.run_command("save")

    def _apply_lint_results(self, view: sublime.View, result: core.LintResult) -> None:
        """Apply lint results on main thread."""
        show_warnings_in_panel(view, result)
        highlight_warnings(view, result)
        update_status_bar(view, result)

    def _apply_error_highlights(self, view: sublime.View, result: core.LintResult) -> None:
        """Apply only error highlights on main thread (no panel)."""
        highlight_warnings(view, result)
        update_status_bar(view, result)

    def on_load_async(self, view: sublime.View) -> None:
        """Check for buildifier on file load if auto_download is enabled."""
        if not is_bazel_file(view):
            return

        # Auto-download buildifier if not found
        if not get_buildifier_path():
            ensure_buildifier(view.window())

    def on_close(self, view: sublime.View) -> None:
        """Clean up when view is closed."""
        view_id = view.id()
        if view_id in _save_guard:
            del _save_guard[view_id]


class BuildifierReplaceContentCommand(sublime_plugin.TextCommand):
    """Internal command to replace entire buffer content."""

    def run(self, edit: sublime.Edit, content: str) -> None:
        # Preserve cursor positions
        selections = list(self.view.sel())

        self.view.replace(edit, sublime.Region(0, self.view.size()), content)

        # Restore cursor positions and ranges (clamped to new content)
        self.view.sel().clear()
        max_point = self.view.size()
        for sel in selections:
            new_a = min(sel.a, max_point)
            new_b = min(sel.b, max_point)
            self.view.sel().add(sublime.Region(new_a, new_b))
