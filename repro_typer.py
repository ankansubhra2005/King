import typer
from typing import Optional, List

app = typer.Typer()

@app.command()
def scan(
    domain: str = typer.Argument(..., help="Target domain"),
    passive: bool = typer.Option(False, "--passive"),
):
    print(f"Scanning {domain}, passive={passive}")

if __name__ == "__main__":
    app()
