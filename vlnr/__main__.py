import typer

from vlnr.cli import main as _discover
from vlnr.cli import agent as _agent
from vlnr.vuln_cli import scan as _scan

app = typer.Typer(
    help="vlnr — discover, scan, and exploit Python supply-chain vulnerabilities",
    no_args_is_help=True,
)

app.command("discover")(_discover)
app.command("scan")(_scan)
app.command("agent")(_agent)


@app.command()
def run() -> None:
    """Chain discover → scan → agent."""
    raise NotImplementedError("vlnr run is implemented in Task 8")


if __name__ == "__main__":
    app()
