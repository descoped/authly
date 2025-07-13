# Git Hooks for Authly

This directory contains git hooks to maintain code quality and consistency in the Authly project.

## Available Hooks

### Pre-commit Hook
- **Purpose**: Ensures code quality before commits
- **Checks**: 
  - Runs `uv run ruff check` on staged Python files
  - Runs `uv run ruff format --check` on staged Python files
  - Offers to auto-format files if needed
- **Benefits**: Prevents CI failures due to linting/formatting issues

## Installation

### Automatic Installation
```bash
# Install hooks for this repository
.githooks/install-hooks.sh
```

### Manual Installation
```bash
# Copy hooks to .git/hooks directory
cp .githooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit

# OR configure git to use .githooks directory
git config core.hooksPath .githooks
```

## Usage

### Normal Workflow
Git hooks run automatically:
```bash
git add src/authly/api/oidc_router.py
git commit -m "Fix XSS vulnerability"
# Hook runs automatically, checks code, and may auto-format
```

### Manual Hook Execution
```bash
# Run pre-commit hook manually
.githooks/pre-commit
```

### Bypass Hooks (Not Recommended)
```bash
# Skip hooks for emergency commits
git commit --no-verify -m "Emergency fix"
```

## Hook Behavior

### Pre-commit Flow
1. **Check for staged Python files** - Only runs if Python files are staged
2. **Run ruff check** - Fails commit if linting errors found
3. **Check formatting** - Detects files that need formatting
4. **Auto-format option** - Asks if you want to auto-format files
5. **Re-stage files** - Automatically re-stages formatted files
6. **Proceed with commit** - Allows commit if all checks pass

### Example Output
```
[PRE-COMMIT] Running pre-commit checks...
[PRE-COMMIT] Checking staged Python files:
  - src/authly/api/oidc_router.py

[PRE-COMMIT] Running ruff check...
[PRE-COMMIT] Ruff check passed!
[PRE-COMMIT] Checking code formatting...
[PRE-COMMIT] Some files need formatting:
  - Would reformat: src/authly/api/oidc_router.py

Auto-format these files? [y/N]: y
[PRE-COMMIT] Auto-formatting files...
[PRE-COMMIT] Re-staged formatted file: src/authly/api/oidc_router.py
[PRE-COMMIT] Files formatted and re-staged!
[PRE-COMMIT] All pre-commit checks passed! 🎉
```

## Configuration

### Hook Settings
The pre-commit hook can be customized by editing `.githooks/pre-commit`:

```bash
# Enable/disable test running (currently commented out)
# Uncomment these lines to run tests before commit:
# print_status "Running tests..."
# if uv run pytest tests/ -x --tb=short; then
#     print_success "Tests passed!"
# else
#     print_error "Tests failed!"
#     exit 1
# fi
```

### Ruff Configuration
Ruff behavior is controlled by `pyproject.toml`:
```toml
[tool.ruff]
line-length = 100
target-version = "py311"

[tool.ruff.lint]
select = ["E", "F", "W", "C90", "I", "N", "UP", "YTT", "S", "BLE", "FBT", "B", "A", "COM", "C4", "DTZ", "T10", "EM", "EXE", "FA", "ISC", "ICN", "G", "INP", "PIE", "T20", "PYI", "PT", "Q", "RSE", "RET", "SLF", "SLOT", "SIM", "TID", "TCH", "INT", "ARG", "PTH", "TD", "FIX", "ERA", "PD", "PGH", "PL", "TRY", "FLY", "NPY", "AIR", "PERF", "FURB", "LOG", "RUF"]
```

## Benefits

### For Developers
- **Immediate feedback** - Catch issues before CI
- **Consistent formatting** - Automatic code formatting
- **Reduced CI failures** - Pre-validate before push
- **Time savings** - No need to manually run ruff commands

### For the Project
- **Code consistency** - Enforced formatting standards
- **Quality assurance** - Automated linting checks
- **Faster CI** - Fewer failed builds
- **Better collaboration** - Consistent code style

## Troubleshooting

### Hook Not Running
```bash
# Check if hooks are installed
ls -la .git/hooks/pre-commit
# or
git config core.hooksPath

# Reinstall hooks
.githooks/install-hooks.sh
```

### Permission Issues
```bash
# Make hooks executable
chmod +x .githooks/pre-commit
chmod +x .git/hooks/pre-commit
```

### UV Not Found
```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh
# or
pip install uv
```

### Disable Hooks Temporarily
```bash
# For one commit
git commit --no-verify -m "Skip hooks"

# Disable permanently (not recommended)
git config core.hooksPath ""
```

## Contributing

When adding new hooks:
1. Create the hook script in `.githooks/`
2. Make it executable: `chmod +x .githooks/new-hook`
3. Update the installer script
4. Update this README
5. Test the hook thoroughly

### Hook Best Practices
- **Fast execution** - Keep hooks lightweight
- **Clear output** - Use colored, informative messages
- **Graceful failure** - Provide helpful error messages
- **User choice** - Allow users to fix issues or abort
- **Non-destructive** - Don't modify files without permission