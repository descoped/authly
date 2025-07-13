#!/bin/bash
# Install Git hooks for Authly development

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[HOOK INSTALLER]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[HOOK INSTALLER]${NC} $1"
}

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GIT_HOOKS_DIR="$SCRIPT_DIR/../.git/hooks"

print_status "Installing Authly git hooks..."

# Check if we're in a git repository
if [ ! -d "$SCRIPT_DIR/../.git" ]; then
    echo "Error: Not in a git repository"
    exit 1
fi

# Create hooks directory if it doesn't exist
mkdir -p "$GIT_HOOKS_DIR"

# Install pre-commit hook
if [ -f "$SCRIPT_DIR/pre-commit" ]; then
    cp "$SCRIPT_DIR/pre-commit" "$GIT_HOOKS_DIR/pre-commit"
    chmod +x "$GIT_HOOKS_DIR/pre-commit"
    print_success "Installed pre-commit hook"
else
    echo "Warning: pre-commit hook not found"
fi

# Optional: Set git hooks path (alternative approach)
print_status "Configuring git to use project hooks directory..."
git config core.hooksPath .githooks

print_success "Git hooks installed successfully!"
print_status "The following hooks are now active:"
print_status "  - pre-commit: Runs ruff check and format before commits"
echo
print_status "To run hooks manually:"
print_status "  .githooks/pre-commit"
echo
print_status "To bypass hooks (not recommended):"
print_status "  git commit --no-verify"