"""CLI tree visualization for Authly commands."""

import click


def generate_tree(
    group: click.Group, prefix: str = "", is_last: bool = True, collect_only: bool = False
) -> str | list[tuple[str, str]]:
    """Generate a tree representation of a Click command group.

    If collect_only is True, returns a list of (tree_line, description) tuples
    for later alignment. Otherwise returns the formatted string.
    """
    lines = []
    entries = [] if collect_only else None

    # Get all commands in the group
    commands = sorted(group.commands.items())

    for i, (name, cmd) in enumerate(commands):
        is_last_cmd = i == len(commands) - 1

        # Determine the connector
        connector = "└── " if is_last_cmd else "├── "
        tree_part = f"{prefix}{connector}{name}"

        # Get command help text if available
        help_text = ""
        if cmd.help:
            # Get first non-empty line of help text
            help_lines = [line.strip() for line in cmd.help.split("\n") if line.strip()]
            if help_lines:
                help_text = help_lines[0][:100]  # First line, max 100 chars

        if collect_only:
            entries.append((tree_part, help_text))
        else:
            if help_text:
                lines.append(f"{tree_part}  # {help_text}")
            else:
                lines.append(tree_part)

        # If it's a group, recurse
        if isinstance(cmd, click.Group):
            extension = "    " if is_last_cmd else "│   "
            subtree = generate_tree(cmd, prefix + extension, is_last_cmd, collect_only)
            if collect_only:
                entries.extend(subtree)
            else:
                if subtree:
                    lines.append(subtree)
        else:
            # For regular commands, show ALL options with descriptions
            if cmd.params:
                extension = "    " if is_last_cmd else "│   "
                options = [p for p in cmd.params if isinstance(p, click.Option)]
                for j, opt in enumerate(options):  # Show ALL options
                    is_last_opt = j == len(options) - 1
                    opt_connector = "└── " if is_last_opt else "├── "
                    opt_names = ", ".join(opt.opts)
                    opt_tree_part = f"{prefix}{extension}{opt_connector}{opt_names}"

                    # Get option help text
                    opt_help = ""
                    if opt.help:
                        opt_help = opt.help.replace("\n", " ").strip()[:80]  # Clean and limit length
                    elif opt.is_flag:
                        opt_help = "Flag option"
                    elif opt.default is not None and not opt.required:
                        opt_help = f"Default: {opt.default}"
                    elif opt.required:
                        opt_help = "Required"

                    if collect_only:
                        entries.append((opt_tree_part, opt_help))
                    else:
                        if opt_help:
                            lines.append(f"{opt_tree_part}  # {opt_help}")
                        else:
                            lines.append(opt_tree_part)

    if collect_only:
        return entries
    return "\n".join(lines)


def get_command_tree(cli: click.Group, aligned: bool = True) -> str:
    """Get a tree representation of all CLI commands."""
    if aligned:
        # Collect all entries first to calculate alignment
        entries = [("authly", "")]
        entries.extend(generate_tree(cli, collect_only=True))

        # Find the maximum width for the tree part
        max_tree_width = max(len(tree_part) for tree_part, _ in entries)

        # Add some padding
        column_position = max_tree_width + 2

        # Format with aligned descriptions
        lines = []
        for tree_part, description in entries:
            if description:
                # Calculate padding needed
                padding = column_position - len(tree_part)
                lines.append(f"{tree_part}{' ' * padding}# {description}")
            else:
                lines.append(tree_part)

        return "\n".join(lines)
    else:
        # Non-aligned version (original)
        tree = ["authly"]
        tree.append(generate_tree(cli))
        return "\n".join(tree)


def print_command_tree(cli: click.Group, aligned: bool = True) -> None:
    """Print a tree representation of all CLI commands."""
    click.echo(get_command_tree(cli, aligned))


# Add tree command to existing CLI
@click.command()
@click.pass_context
def tree(ctx):
    """Display command tree structure."""
    # Get the root CLI group
    root_cli = ctx.find_root().command

    if isinstance(root_cli, click.Group):
        click.echo("Authly CLI Command Tree")
        click.echo("=" * 40)
        print_command_tree(root_cli)
    else:
        click.echo("Error: Could not generate command tree")
