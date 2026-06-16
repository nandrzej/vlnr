import asyncio
import json
import logging
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import typer

from vlnr.agent import AgentLoop
from vlnr.agent_models import AgentState
from vlnr.cli import agent as _agent
from vlnr.cli import main as _discover
from vlnr.cli import run_pipeline
from vlnr.llm import LLMClient
from vlnr.vuln_cli import run_scan
from vlnr.vuln_cli import scan as _scan
from vlnr.vuln_models import PackageFindings, Slice

logger = logging.getLogger(__name__)

app = typer.Typer(
    help="vlnr — discover, scan, and exploit Python supply-chain vulnerabilities",
    no_args_is_help=True,
)

app.command("discover")(_discover)
app.command("scan")(_scan)
app.command("agent")(_agent)


@app.command()
def run(
    out_dir: Path = typer.Option(..., "--out-dir", file_okay=False, dir_okay=True),
    osv_dump: Path = typer.Option(..., "--osv-dump"),
    packages: str | None = typer.Option(None, "--packages"),
    pypi_json: Path | None = typer.Option(None, "--pypi-json", exists=True, dir_okay=False),
    limit: int = typer.Option(100, "--limit"),
    llm_discovery: bool = typer.Option(False, "--llm-discovery"),
    llm_triage: bool = typer.Option(False, "--llm-triage"),
    llm_poc: bool = typer.Option(False, "--llm-poc"),
    budget: float = typer.Option(10.0, "--budget"),
    max_iterations: int = typer.Option(5, "--max-iterations"),
    skip_scan: bool = typer.Option(False, "--skip-scan"),
    skip_agent: bool = typer.Option(False, "--skip-agent"),
) -> None:
    """Chain discover → scan → agent into a single command."""
    if (packages is None) == (pypi_json is None):
        raise typer.BadParameter("Specify exactly one of --packages or --pypi-json.")

    out_dir.mkdir(parents=True, exist_ok=True)

    needs_llm = (not skip_agent) or llm_discovery or llm_triage or llm_poc
    llm_client: LLMClient | None = None
    if needs_llm:
        try:
            llm_client = LLMClient()
        except Exception as e:
            logger.exception("LLM client initialization failed")
            print(f"LLM client initialization failed: {type(e).__name__}: {e}", file=sys.stderr)
            raise typer.Exit(1) from e

    _run_stage(
        "discover",
        _discover_stage,
        osv_dump=osv_dump,
        packages=packages,
        pypi_json=pypi_json,
        limit=limit,
        llm_discovery=llm_discovery,
        out=out_dir / "candidates.json",
    )

    candidates: list[dict[str, Any]] = []
    if not skip_agent:
        candidates = json.loads((out_dir / "candidates.json").read_text())

    if not skip_scan:
        _run_stage(
            "scan",
            _scan_stage,
            candidates=out_dir / "candidates.json",
            out_dir=out_dir / "findings",
            max_packages=0,
            max_files_per_pkg=0,
            llm_client=llm_client,
            generate_pocs=llm_poc,
        )

    if not skip_agent:
        _run_stage(
            "agent",
            _agent_stage,
            out_dir=out_dir,
            candidates=candidates,
            llm_client=llm_client,
            budget=budget,
            max_iterations=max_iterations,
            scanned=[] if skip_scan else None,
        )


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


def _run_stage(name: str, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
    try:
        fn(*args, **kwargs)
    except typer.Exit, typer.BadParameter:
        raise
    except Exception as e:
        logger.exception(f"Stage {name} failed")
        print(f"Stage {name} failed: {type(e).__name__}: {e}", file=sys.stderr)
        raise typer.Exit(1) from e


def _discover_stage(
    osv_dump: Path,
    packages: str | None,
    pypi_json: Path | None,
    limit: int,
    llm_discovery: bool,
    out: Path,
) -> None:
    asyncio.run(
        run_pipeline(
            osv_dump=osv_dump,
            packages=packages,
            pypi_json=pypi_json,
            limit=limit,
            llm_discovery=llm_discovery,
            out=out,
        ),
    )


def _scan_stage(
    candidates: Path,
    out_dir: Path,
    max_packages: int,
    max_files_per_pkg: int,
    llm_client: LLMClient | None,
    generate_pocs: bool,
) -> None:
    run_scan(
        candidates_path=candidates,
        out_dir=out_dir,
        max_packages=max_packages,
        max_files_per_pkg=max_files_per_pkg,
        llm_client=llm_client,
        generate_pocs=generate_pocs,
    )


# `llm_client` is `LLMClient | None` because the orchestrator's `needs_llm` gate in Task 8
# constructs an `LLMClient` only when `not skip_agent` or any `--llm-*` flag is set. With
# `vlnr run --skip-agent` and no `--llm-triage`/`--llm-poc`/`--llm-discovery`, `llm_client`
# is `None` and the orchestrator calls `_scan_stage(..., llm_client=None, generate_pocs=False)`.
# `run_scan` must handle `llm_client=None` gracefully: no LLM calls, only deterministic
# static analysis inside `process_package`. This is already supported by `process_package`'s
# `if llm_client:` guards (`vlnr/vuln_cli.py:249`), so no change is needed in `_scan_stage`.


def _agent_stage(
    out_dir: Path,
    candidates: list[dict[str, Any]],
    llm_client: LLMClient | None,
    budget: float,
    max_iterations: int,
    scanned: list[str] | None = None,
) -> None:
    if llm_client is None:
        raise RuntimeError(
            "_agent_stage requires a non-None llm_client (orchestrator gates construction on needs_llm).",
        )
    state = build_initial_state(out_dir, candidates, max_iterations, budget, scanned=scanned)
    loop = AgentLoop(llm_client, out_dir=str(out_dir / "findings"))
    loop.run(state, state_path=str(out_dir / "agent_session.json"))


if __name__ == "__main__":
    app()
