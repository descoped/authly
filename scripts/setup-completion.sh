#!/bin/bash
# Setup shell completion for Authly CLI
# Supports bash, zsh, and fish

set -e

SCRIPT_NAME="authly"
PYTHON_CMD="python -m authly"

# Detect the shell
detect_shell() {
    if [ -n "$BASH_VERSION" ]; then
        echo "bash"
    elif [ -n "$ZSH_VERSION" ]; then
        echo "zsh"
    elif [ -n "$FISH_VERSION" ]; then
        echo "fish"
    else
        # Try to detect from SHELL variable
        case "$SHELL" in
            */bash) echo "bash" ;;
            */zsh) echo "zsh" ;;
            */fish) echo "fish" ;;
            *) echo "unknown" ;;
        esac
    fi
}

# Setup bash completion
setup_bash() {
    echo "Setting up bash completion for Authly..."
    
    # Generate completion script
    _AUTHLY_COMPLETE=bash_source $PYTHON_CMD > /tmp/authly-complete.bash
    
    # Determine where to install
    if [ -d "$HOME/.local/share/bash-completion/completions" ]; then
        COMPLETION_DIR="$HOME/.local/share/bash-completion/completions"
    elif [ -d "/usr/local/share/bash-completion/completions" ] && [ -w "/usr/local/share/bash-completion/completions" ]; then
        COMPLETION_DIR="/usr/local/share/bash-completion/completions"
    else
        COMPLETION_DIR="$HOME/.bash_completion.d"
        mkdir -p "$COMPLETION_DIR"
    fi
    
    cp /tmp/authly-complete.bash "$COMPLETION_DIR/authly"
    
    # Add to bashrc if not already there
    if ! grep -q "authly completion" "$HOME/.bashrc" 2>/dev/null; then
        echo "" >> "$HOME/.bashrc"
        echo "# Authly CLI completion" >> "$HOME/.bashrc"
        echo "[ -f $COMPLETION_DIR/authly ] && source $COMPLETION_DIR/authly" >> "$HOME/.bashrc"
    fi
    
    echo "✅ Bash completion installed to $COMPLETION_DIR/authly"
    echo "   Restart your shell or run: source $HOME/.bashrc"
}

# Setup zsh completion
setup_zsh() {
    echo "Setting up zsh completion for Authly..."
    
    # Generate completion script
    _AUTHLY_COMPLETE=zsh_source $PYTHON_CMD > /tmp/authly-complete.zsh
    
    # Determine where to install
    if [ -d "$HOME/.local/share/zsh/site-functions" ]; then
        COMPLETION_DIR="$HOME/.local/share/zsh/site-functions"
    elif [ -d "/usr/local/share/zsh/site-functions" ] && [ -w "/usr/local/share/zsh/site-functions" ]; then
        COMPLETION_DIR="/usr/local/share/zsh/site-functions"
    else
        COMPLETION_DIR="$HOME/.zsh/completions"
        mkdir -p "$COMPLETION_DIR"
    fi
    
    cp /tmp/authly-complete.zsh "$COMPLETION_DIR/_authly"
    
    # Add to zshrc if not already there
    if ! grep -q "authly completion" "$HOME/.zshrc" 2>/dev/null; then
        echo "" >> "$HOME/.zshrc"
        echo "# Authly CLI completion" >> "$HOME/.zshrc"
        echo "fpath=($COMPLETION_DIR \$fpath)" >> "$HOME/.zshrc"
        echo "autoload -U compinit && compinit" >> "$HOME/.zshrc"
    fi
    
    echo "✅ Zsh completion installed to $COMPLETION_DIR/_authly"
    echo "   Restart your shell or run: source $HOME/.zshrc"
}

# Setup fish completion
setup_fish() {
    echo "Setting up fish completion for Authly..."
    
    # Generate completion script
    _AUTHLY_COMPLETE=fish_source $PYTHON_CMD > /tmp/authly-complete.fish
    
    # Fish completion directory
    COMPLETION_DIR="$HOME/.config/fish/completions"
    mkdir -p "$COMPLETION_DIR"
    
    cp /tmp/authly-complete.fish "$COMPLETION_DIR/authly.fish"
    
    echo "✅ Fish completion installed to $COMPLETION_DIR/authly.fish"
    echo "   Completion should be available immediately"
}

# Main execution
main() {
    # Check if Click is installed with completion support
    if ! python -c "import click" 2>/dev/null; then
        echo "❌ Error: Click is not installed"
        exit 1
    fi
    
    DETECTED_SHELL=$(detect_shell)
    
    # Allow override with command line argument
    if [ -n "$1" ]; then
        DETECTED_SHELL="$1"
    fi
    
    echo "Detected shell: $DETECTED_SHELL"
    
    case "$DETECTED_SHELL" in
        bash)
            setup_bash
            ;;
        zsh)
            setup_zsh
            ;;
        fish)
            setup_fish
            ;;
        *)
            echo "❌ Unsupported or unknown shell: $DETECTED_SHELL"
            echo "   Please specify shell: $0 [bash|zsh|fish]"
            exit 1
            ;;
    esac
}

# Show help
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "Setup tab completion for Authly CLI"
    echo ""
    echo "Usage: $0 [shell]"
    echo ""
    echo "Shells:"
    echo "  bash    Setup bash completion"
    echo "  zsh     Setup zsh completion"
    echo "  fish    Setup fish completion"
    echo ""
    echo "If no shell is specified, will try to detect current shell"
    exit 0
fi

main "$@"