"""
KING Verbose Logger
Central module that controls verbosity across all engines.
When --verbose is enabled, all engines log their activity to the console in real-time
using Rich's formatted output — similar to subfinder -v.
"""
import asyncio
import logging
import sys
from typing import Optional, List, Callable
from rich.logging import RichHandler
from rich.console import Console
from rich.text import Text

# Shared console (imported everywhere verbose output is needed)
verbose_console = Console(stderr=True)

# Global verbose flag — set once by CLI before scan starts
VERBOSE = False


def enable_verbose():
    """Enable verbose mode — call this at CLI startup when -v is passed."""
    global VERBOSE
    VERBOSE = True

    # Configure root logger to use Rich handler so all `log.debug()/info()` calls
    # from every engine (recon_engine, crawler, etc.) print to the terminal.
    handler = RichHandler(
        console=verbose_console,
        show_time=True,
        show_path=False,
        markup=True,
        rich_tracebacks=False,
        log_time_format="[%H:%M:%S]",
    )
    handler.setFormatter(logging.Formatter("%(message)s"))

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(handler)

    # Silence noisy third-party libraries even in verbose mode
    for noisy in ["httpx", "httpcore", "asyncio", "urllib3", "websockets"]:
        logging.getLogger(noisy).setLevel(logging.WARNING)


def is_verbose() -> bool:
    return VERBOSE


# ── Live Event Printer ────────────────────────────────────────────────────────
# Engines call these helpers directly for structured, colorful verbose output.

def v_found(category: str, value: str, source: str = ""):
    """Print a discovered item (subdomain, asset, endpoint)."""
    if not VERBOSE:
        return
    src = f" [dim]← {source}[/dim]" if source else ""
    verbose_console.print(f"  [bold green][+][/bold green] [cyan]{category}[/cyan]: [white]{value}[/white]{src}")


def v_info(module: str, message: str):
    """Print an informational verbose message from a module."""
    if not VERBOSE:
        return
    verbose_console.print(f"  [bold dim][~][/bold dim] [yellow]{module}[/yellow]: [dim]{message}[/dim]")


def v_probe(url: str, status: int, extra: str = ""):
    """Print a live probe result (HTTP status)."""
    if not VERBOSE:
        return
    color = "green" if status < 300 else "yellow" if status < 400 else "dim red" if status < 500 else "red"
    ext = f"  [dim]{extra}[/dim]" if extra else ""
    verbose_console.print(f"  [bold dim]→[/bold dim] [{color}]{status}[/{color}]  [white]{url}[/white]{ext}")


def v_finding(finding_type: str, severity: str, url: str, evidence: str = ""):
    """Print a finding as it's discovered (real-time)."""
    if not VERBOSE:
        return
    sev_colors = {
        "critical": "bold red",
        "high":     "orange3",
        "medium":   "yellow",
        "low":      "green",
        "info":     "dim",
    }
    color = sev_colors.get(severity.lower(), "white")
    ev = f"  [dim]{evidence[:80]}[/dim]" if evidence else ""
    verbose_console.print(
        f"  [bold red][!][/bold red] [{color}]{severity.upper()}[/{color}]"
        f"  [yellow]{finding_type}[/yellow]  [cyan]{url[:70]}[/cyan]{ev}"
    )


def v_tool(tool_name: str, cmd: str):
    """Print when an external tool is being invoked."""
    if not VERBOSE:
        return
    verbose_console.print(f"  [bold magenta][>][/bold magenta] [magenta]{tool_name}[/magenta]: [dim]{cmd}[/dim]")


def v_section(title: str):
    """Print a verbose section separator."""
    if not VERBOSE:
        return
    verbose_console.rule(f"[dim]{title}[/dim]", style="dim")


# ── Live Subprocess Streaming ─────────────────────────────────────────────────

async def run_tool_live(
    tool_name: str,
    cmd: List[str],
    parse_fn: Optional[Callable[[str], Optional[str]]] = None,
    always_show: bool = False,
    timeout: int = 300,
) -> List[str]:
    """
    Run an external tool as a subprocess and stream its stdout line-by-line
    to the terminal in real time (when verbose mode is on).

    Args:
        tool_name:   Display name for the tool (e.g. "katana", "dalfox")
        cmd:         Full command list, e.g. ["katana", "-u", "https://example.com"]
        parse_fn:    Optional function that receives a raw line and returns a clean
                     display string (or None to suppress that line). If omitted,
                     every non-empty line is printed and returned.
        always_show: If True, stream output even when VERBOSE is off.
        timeout:     Seconds before we give up waiting for the process.

    Returns:
        List of all output lines collected.
    """
    cmd_str = " ".join(cmd)
    v_tool(tool_name, cmd_str)

    collected: List[str] = []

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        v_info(tool_name, "not installed — skipping (install it to enable)")
        return []
    except Exception as e:
        v_info(tool_name, f"failed to start: {e}")
        return []

    async def read_stream(stream, is_stderr=False):
        while True:
            try:
                line_bytes = await asyncio.wait_for(stream.readline(), timeout=timeout)
            except asyncio.TimeoutError:
                break
            if not line_bytes:
                break
            line = line_bytes.decode("utf-8", errors="replace").strip()
            if not line:
                continue

            if is_stderr:
                # Only print stderr if it looks like a real error, not noise
                if VERBOSE and any(kw in line.lower() for kw in ["error", "fatal", "panic"]):
                    v_info(f"{tool_name}:err", line[:120])
                continue

            # Apply parse function
            display = parse_fn(line) if parse_fn else line
            if display is None:
                continue  # parse_fn suppressed this line

            collected.append(display)

            if VERBOSE or always_show:
                verbose_console.print(
                    f"  [bold green][+][/bold green] [magenta]{tool_name}[/magenta]: [white]{display[:120]}[/white]"
                )

    try:
        await asyncio.wait_for(
            asyncio.gather(
                read_stream(proc.stdout, is_stderr=False),
                read_stream(proc.stderr, is_stderr=True),
            ),
            timeout=timeout + 5,
        )
    except asyncio.TimeoutError:
        v_info(tool_name, f"timed out after {timeout}s — partial results returned")
        proc.kill()

    try:
        await asyncio.wait_for(proc.wait(), timeout=5)
    except asyncio.TimeoutError:
        pass

    return collected
