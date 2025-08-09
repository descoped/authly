"""Shell completion support for Authly CLI."""

import os
import sys
from pathlib import Path

import click
from click.shell_completion import get_completion_class


def detect_shell() -> str:
    """Detect the current shell."""
    # Check SHELL environment variable
    shell_path = os.environ.get("SHELL", "")

    if "bash" in shell_path:
        return "bash"
    elif "zsh" in shell_path:
        return "zsh"
    elif "fish" in shell_path:
        return "fish"

    # Check PS1 or other shell-specific variables
    if os.environ.get("ZSH_VERSION"):
        return "zsh"
    elif os.environ.get("BASH_VERSION"):
        return "bash"
    elif os.environ.get("FISH_VERSION"):
        return "fish"

    # Default to bash
    return "bash"


def get_completion_path(shell: str) -> Path:
    """Get the appropriate completion file path for the shell."""
    home = Path.home()

    if shell == "bash":
        # Try standard locations in order of preference
        candidates = [
            home / ".local" / "share" / "bash-completion" / "completions",
            home / ".bash_completion.d",
            Path("/etc/bash_completion.d"),
        ]
        for path in candidates:
            if path.exists() or not path.exists():
                path.mkdir(parents=True, exist_ok=True)
                return path / "authly"

    elif shell == "zsh":
        # Zsh completion paths
        completion_dir = home / ".zfunc"
        completion_dir.mkdir(exist_ok=True)
        return completion_dir / "_authly"

    elif shell == "fish":
        # Fish completion path
        completion_dir = home / ".config" / "fish" / "completions"
        completion_dir.mkdir(parents=True, exist_ok=True)
        return completion_dir / "authly.fish"

    return home / f".authly-completion.{shell}"


def generate_completion_script(shell: str) -> str:
    """Generate completion script for the given shell."""
    from authly.__main__ import cli

    completion_cls = get_completion_class(shell)
    if completion_cls is None:
        raise ValueError(f"Unsupported shell: {shell}")

    # Create completion instance
    complete_var = "_AUTHLY_COMPLETE"
    completion = completion_cls(cli, {}, "authly", complete_var)

    # Add wrapper for python -m authly
    script = completion.source()

    # Add support for both 'authly' and 'python -m authly'
    if shell == "bash":
        script += "\n\n# Also support 'python -m authly' invocation\n"
        script += "complete -o nosort -F _authly_completion python -m authly\n"
    elif shell == "zsh":
        script += "\n\n# Also support 'python -m authly' invocation\n"
        script += "compdef _authly_completion 'python -m authly'\n"

    return script


def install_shell_completion() -> bool:
    """Install shell completion for the current shell."""
    try:
        shell = detect_shell()
        click.echo(f"🔍 Detected shell: {shell}")

        # Generate completion script
        script = generate_completion_script(shell)

        # Get installation path
        completion_path = get_completion_path(shell)

        # Write completion file
        completion_path.write_text(script)
        click.echo(f"✅ Installed completion to: {completion_path}")

        # Instructions for activation
        if shell == "bash":
            bashrc = Path.home() / ".bashrc"
            source_line = f"source {completion_path}"

            # Check if already in bashrc
            if bashrc.exists() and source_line not in bashrc.read_text():
                click.echo("\n📝 Add this line to your ~/.bashrc:")
                click.echo(f"   {source_line}")

            click.echo("\n🔄 Activate now with:")
            click.echo(f"   source {completion_path}")

        elif shell == "zsh":
            zshrc = Path.home() / ".zshrc"
            fpath_line = f"fpath=({completion_path.parent} $fpath)"

            if zshrc.exists() and fpath_line not in zshrc.read_text():
                click.echo("\n📝 Add these lines to your ~/.zshrc:")
                click.echo(f"   {fpath_line}")
                click.echo("   autoload -U compinit && compinit")

            click.echo("\n🔄 Restart your shell or run:")
            click.echo("   source ~/.zshrc")

        elif shell == "fish":
            click.echo("\n✅ Completion should be available immediately in fish!")

        click.echo("\n🎉 Tab completion is ready! Try:")
        click.echo("   python -m authly [TAB]")
        click.echo("   python -m authly admin [TAB]")

        return True

    except Exception as e:
        click.echo(f"❌ Failed to install completion: {e}", err=True)
        return False


def show_shell_completion() -> None:
    """Show completion script for the current shell without installing."""
    try:
        shell = detect_shell()
        script = generate_completion_script(shell)
        click.echo(script)
    except Exception as e:
        click.echo(f"Error generating completion: {e}", err=True)
        sys.exit(1)


def check_completion_installed() -> bool:
    """Check if completion is already installed for current shell."""
    shell = detect_shell()
    completion_path = get_completion_path(shell)
    return completion_path.exists()


def maybe_suggest_completion() -> None:
    """Suggest installing completion if not already installed and in interactive shell."""
    # Only suggest in interactive terminals
    if not sys.stdout.isatty():
        return

    # Check if we've already suggested (don't nag)
    config_dir = Path.home() / ".config" / "authly"
    config_dir.mkdir(parents=True, exist_ok=True)

    marker_file = config_dir / ".completion_suggested"
    if marker_file.exists():
        return

    # Check if completion is already installed
    if check_completion_installed():
        return

    # Don't suggest if running in Docker container
    if os.path.exists("/.dockerenv") or os.environ.get("AUTHLY_STANDALONE"):
        return

    # Suggest completion installation
    click.echo("\n💡 Tip: Enable tab completion for easier CLI usage!", err=True)
    click.echo("   Run: python -m authly --install-completion", err=True)
    click.echo("", err=True)

    # Mark as suggested
    marker_file.touch()
