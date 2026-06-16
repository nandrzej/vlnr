# ruff: noqa: E402
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


from pathlib import Path
from typing import Any

from vlnr.agent_models import AgentState
from vlnr.vuln_models import PackageFindings, Slice


def build_initial_state(
    out_dir: Path,
    candidates: list[dict[str, Any]],
    max_iterations: int,
    budget: float,
    scanned: list[str] | None = None,
) -> AgentState:
    names = [pkg["name"] for pkg in candidates]
    if scanned is not None and not scanned:
        return AgentState(
            scanned_packages=[],
            findings=[],
            slices=[],
            candidate_pool=names,
            max_iterations=max_iterations,
            budget_remaining=budget,
        )
    findings: list[PackageFindings] = []
    slices: list[Slice] = []
    findings_dir = out_dir / "findings"
    for name in names:
        f_path = findings_dir / f"{name}-findings.json"
        if f_path.exists():
            findings.append(PackageFindings.model_validate_json(f_path.read_text()))
        s_path = findings_dir / f"{name}-slices.jsonl"
        if s_path.exists():
            for line in s_path.read_text().splitlines():
                if line.strip():
                    slices.append(Slice.model_validate_json(line))
    return AgentState(
        scanned_packages=names if scanned is None else scanned,
        findings=findings,
        slices=slices,
        candidate_pool=names,
        max_iterations=max_iterations,
        budget_remaining=budget,
    )


if __name__ == "__main__":
    app()
