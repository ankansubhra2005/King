"""
CLI sub-commands for managing custom wordlists and payloads.
Usage:
    python -m cli.wordlists list
    python -m cli.wordlists add --category xss /path/to/my_payloads.txt
    python -m cli.wordlists preview --category subdomains
"""
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from pathlib import Path
from typing import Optional

from app.core.payload_manager import list_available, install_custom, load_wordlist, CUSTOM_DIR

app = typer.Typer(name="wordlists", help="🗂️  Manage custom wordlists and payload files")
console = Console()

VALID_CATEGORIES = ["subdomains", "directories", "xss", "ssrf", "lfi", "sqli", "extensions", "headers"]


@app.command("list")
def list_wordlists(category: Optional[str] = typer.Option(None, "--category", "-c")):
    """
    List all available wordlists with entry counts.

    Shows both built-in defaults and any custom files you've added.
    """
    data = list_available(category)
    table = Table(title="🗂️  Available Wordlists & Payloads", show_lines=True)
    table.add_column("Category", style="cyan", min_width=14)
    table.add_column("Default Entries", style="green", min_width=14)
    table.add_column("Custom Files", style="yellow")
    table.add_column("Total Entries", style="bold white", min_width=12)

    for cat, info in data.items():
        custom_str = "\n".join(
            f"{name}: {count} entries"
            for name, count in info["custom_files"].items()
        ) or "[dim]none[/dim]"
        table.add_row(
            cat,
            str(info["default_entries"]),
            custom_str,
            f"[bold]{info['total_entries']}[/bold]",
        )
    console.print(table)
    console.print(
        f"\n[dim]Custom files directory:[/dim] [cyan]{CUSTOM_DIR}[/cyan]\n"
        f"[dim]Drop any .txt file there with a recognizable name to auto-load it.[/dim]\n"
        f"[dim]Example: [green]xss_my_custom.txt[/green] → auto-loaded as XSS payloads[/dim]"
    )


@app.command("add")
def add_wordlist(
    path: str = typer.Argument(..., help="Path to your .txt wordlist/payload file"),
    category: str = typer.Option(..., "--category", "-c",
                                  help=f"Category: {', '.join(VALID_CATEGORIES)}"),
):
    """
    Add a custom wordlist/payload file to the platform.

    The file will be merged with built-in defaults on all future scans.

    Examples:
    \b
        python -m cli.wordlists add ~/my_xss.txt --category xss
        python -m cli.wordlists add ~/subs.txt --category subdomains
    """
    if category not in VALID_CATEGORIES:
        console.print(f"[red]❌ Invalid category '{category}'. Choose from: {', '.join(VALID_CATEGORIES)}[/red]")
        raise typer.Exit(1)

    try:
        dest = install_custom(path, category)
        # Count entries
        entries = load_wordlist(category)
        console.print(Panel.fit(
            f"[bold green]✅ Successfully added![/bold green]\n\n"
            f"[dim]File:[/dim] [cyan]{Path(path).name}[/cyan]\n"
            f"[dim]Category:[/dim] [yellow]{category}[/yellow]\n"
            f"[dim]Saved to:[/dim] {dest}\n"
            f"[dim]Total '{category}' entries now:[/dim] [bold]{len(entries)}[/bold]",
            border_style="green"
        ))
    except FileNotFoundError:
        console.print(f"[red]❌ File not found: {path}[/red]")
        raise typer.Exit(1)


@app.command("preview")
def preview_wordlist(
    category: str = typer.Argument(..., help=f"Category to preview: {', '.join(VALID_CATEGORIES)}"),
    limit: int = typer.Option(30, "--limit", "-n", help="Number of entries to show"),
):
    """
    Preview the merged (built-in + custom) wordlist for a category.

    Example:
    \b
        python -m cli.wordlists preview xss --limit 20
    """
    if category not in VALID_CATEGORIES:
        console.print(f"[red]❌ Invalid category '{category}'.[/red]")
        raise typer.Exit(1)

    entries = load_wordlist(category)
    console.print(f"\n[cyan]📋 {category.upper()} Wordlist — {len(entries)} total entries[/cyan]\n")
    for i, entry in enumerate(entries[:limit], 1):
        console.print(f"  [dim]{i:3}[/dim]  {entry}")
    if len(entries) > limit:
        console.print(f"\n  [dim]... and {len(entries) - limit} more entries[/dim]")


@app.command("remove")
def remove_wordlist(
    category: str = typer.Argument(..., help="Category of the file to remove"),
    filename: str = typer.Argument(..., help="Filename to remove (as shown in 'list')"),
):
    """Remove a previously added custom wordlist file."""
    target = CUSTOM_DIR / filename
    if not target.exists():
        console.print(f"[red]❌ File not found: {filename}[/red]")
        raise typer.Exit(1)
    target.unlink()
    console.print(f"[green]✅ Removed {filename} from {category} wordlists.[/green]")


if __name__ == "__main__":
    app()
