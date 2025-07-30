#!/bin/bash
# Install git hooks for Authly development
# This script sets up pre-commit hooks with auto-fixing capabilities

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[HOOK-INSTALL]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[HOOK-INSTALL]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[HOOK-INSTALL]${NC} $1"
}

print_error() {
    echo -e "${RED}[HOOK-INSTALL]${NC} $1"
}

# Check if we're in a git repository
if ! git rev-parse --git-dir >/dev/null 2>&1; then
    print_error "Not in a git repository!"
    exit 1
fi

# Get the git root directory
GIT_ROOT=$(git rev-parse --show-toplevel)
HOOKS_DIR="$GIT_ROOT/.git/hooks"
SOURCE_HOOKS_DIR="$GIT_ROOT/.githooks"

print_status "Installing Authly git hooks..."
print_status "Git repository: $GIT_ROOT"
print_status "Hooks directory: $HOOKS_DIR"

# Check if uv is available
if ! command -v uv >/dev/null 2>&1; then
    print_error "uv is not installed or not in PATH"
    print_error "Please install uv: curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
fi

# Create hooks directory if it doesn't exist
mkdir -p "$HOOKS_DIR"

# Install pre-commit hook
PRECOMMIT_SOURCE="$SOURCE_HOOKS_DIR/pre-commit"
PRECOMMIT_TARGET="$HOOKS_DIR/pre-commit"

if [ -f "$PRECOMMIT_SOURCE" ]; then
    # Backup existing hook if it exists
    if [ -f "$PRECOMMIT_TARGET" ]; then
        print_warning "Backing up existing pre-commit hook..."
        cp "$PRECOMMIT_TARGET" "$PRECOMMIT_TARGET.backup.$(date +%s)"
    fi
    
    # Copy and make executable
    cp "$PRECOMMIT_SOURCE" "$PRECOMMIT_TARGET"
    chmod +x "$PRECOMMIT_TARGET"
    print_success "Installed pre-commit hook"
else
    print_error "Pre-commit hook source not found: $PRECOMMIT_SOURCE"
    exit 1
fi

# Set git config for hook path (optional, for global hook directory support)
git config core.hooksPath .githooks 2>/dev/null || true

print_success "Git hooks installed successfully! 🎉"
echo
print_status "Hook features:"
echo "  ✅ Auto-fix ruff linting issues"
echo "  ✅ Auto-format code with ruff"
echo "  ✅ Re-stage fixed files automatically"
echo
print_status "Environment variables:"
echo "  AUTHLY_NO_AUTO_FIX=true  - Disable auto-fixing (manual mode)"
echo
print_status "To test the hooks:"
echo "  1. Make some changes to Python files"
echo "  2. Stage them with: git add <files>"
echo "  3. Commit: git commit -m \"Test commit\""
echo "  4. Watch the hooks auto-fix any issues!"