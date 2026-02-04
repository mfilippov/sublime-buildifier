# Buildifier for Sublime Text

A Sublime Text plugin for formatting and linting Bazel files using [buildifier](https://github.com/bazelbuild/buildtools/tree/master/buildifier).

## Features

- **Format on Save** — Automatically format Bazel files when saving
- **Lint Warnings** — Display lint warnings with squiggly underlines, inline annotations, and output panel
- **Warning Navigation** — Jump to next/previous warning in file
- **Auto-download** — Automatically download buildifier from GitHub releases
- **SHA256 Verification** — Verify downloaded binaries for security
- **Config Support** — Respect `.buildifier.json` configuration files
- **Cross-platform** — Works on macOS, Linux, and Windows (amd64/arm64)

## Supported File Types

| Pattern | Type |
|---------|------|
| `BUILD`, `BUILD.*` | build |
| `WORKSPACE`, `WORKSPACE.*` | workspace |
| `MODULE.bazel` | module |
| `*.bzl`, `*.bzl.*` | bzl |

## Installation

### Package Control (Recommended)

1. Open Command Palette (`Cmd+Shift+P` / `Ctrl+Shift+P`)
2. Select `Package Control: Install Package`
3. Search for `Buildifier` and install

### Manual Installation

1. Clone this repository into your Sublime Text `Packages` directory:
   ```bash
   cd ~/Library/Application\ Support/Sublime\ Text/Packages/  # macOS
   cd ~/.config/sublime-text/Packages/                         # Linux
   cd %APPDATA%\Sublime Text\Packages\                         # Windows

   git clone https://github.com/mfilippov/sublime-buildifier.git Buildifier
   ```

2. Restart Sublime Text

## Commands

Access via Command Palette (`Cmd+Shift+P` / `Ctrl+Shift+P`):

| Command | Description |
|---------|-------------|
| `Buildifier: Format File` | Format the current file |
| `Buildifier: Lint File` | Show lint warnings |
| `Buildifier: Format and Fix` | Format and apply lint fixes |
| `Buildifier: Next Warning` | Jump to next warning in file |
| `Buildifier: Previous Warning` | Jump to previous warning in file |
| `Buildifier: Download/Update` | Download or update buildifier |
| `Buildifier: Show Info` | Show debug information |

## Configuration

Open settings via `Preferences → Package Settings → Buildifier → Settings`.

```json
{
    // Path to buildifier executable (null = auto-download or PATH)
    "buildifier_path": null,

    // Additional arguments to pass to buildifier
    "buildifier_args": [],

    // Timeout in milliseconds
    "buildifier_timeout": 5000,

    // Action on save: "off" | "format" | "lint" | "format+lint"
    "on_save": "format",

    // Strategy: "pre_save_blocking" | "post_save_resave"
    "format_on_save_strategy": "pre_save_blocking",

    // Working directory: "config_dir" | "file_dir" | "project_root" | "custom"
    "working_dir_mode": "config_dir",
    "custom_working_dir": null,

    // Additional file patterns: {"*.star": "default", "DEPS": "build"}
    "additional_file_patterns": {},

    // Warnings: null | "all" | "-positional-args,+unsorted-dict-items"
    "warnings": null,

    // Auto-download buildifier if not found
    "auto_download": true,

    // Auto-update: "never" | "prompt" | "always"
    "auto_update": "prompt",

    // Verify SHA256 when downloading
    "verify_sha256": true,

    // Show warnings in output panel
    "show_warnings_in_panel": true,

    // Highlight warnings in editor
    "highlight_warnings_in_editor": true,

    // Scopes for highlighting (theme-dependent colors)
    "warning_scope": "markup.warning",
    "error_scope": "markup.error",

    // Color for inline annotations (null = use theme error color)
    "annotation_color": null
}
```

### Working Directory Modes

The working directory affects how buildifier finds `.buildifier.json` and resolves relative paths in `Tables`/`AddTables`.

- **config_dir** (default) — Search upward for `.buildifier.json`, use that directory
- **file_dir** — Directory of the current file
- **project_root** — First folder in the Sublime Text project
- **custom** — Use `custom_working_dir` value

### Using .buildifier.json

Create a `.buildifier.json` in your project root:

```json
{
    "indent": 4,
    "tables": ["//path/to/tables.json"]
}
```

With `working_dir_mode: "config_dir"`, buildifier will find and use this config even when editing files in subdirectories.

## Development

### Requirements

- [uv](https://github.com/astral-sh/uv) for dependency management (handles Python automatically)

### Setup

```bash
git clone https://github.com/mfilippov/sublime-buildifier.git
cd sublime-buildifier
uv sync --extra dev
```

### Running Tests

```bash
uv run pytest tests/ -v
```

### Project Structure

```
sublime-buildifier/
├── buildifier_core.py          # Pure Python logic (no Sublime imports)
├── Buildifier.py               # Sublime Text integration
├── Buildifier.sublime-settings # Default settings
├── Default.sublime-commands    # Command palette entries
├── pyproject.toml              # Project configuration
└── tests/
    ├── test_buildifier_core.py        # Unit tests
    ├── test_buildifier_integration.py # Integration tests (require buildifier)
    └── fixtures/                      # Test fixtures
```

The core logic is separated into `buildifier_core.py` to enable testing with pytest outside of Sublime Text.

## License

Apache-2.0 license
