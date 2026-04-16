import asyncio
import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, TaskID

from vlnr.filters import is_target_category
from vlnr.github import get_repo_stars
from vlnr.models import CandidateRecord, PackageInfo, VulnerabilityIndex
from vlnr.osv import load_osv_index
from vlnr.pypi import fetch_packages_from_api, stream_packages_from_jsonl
from vlnr.scorer import score_candidate

app = typer.Typer(help="Vulnerability-aware Python Project Finder")
console = Console()


async def _process_package(
    pkg: PackageInfo,
    vuln_index: VulnerabilityIndex,
    downloads_map: dict[str, int],
    candidates: list[CandidateRecord],
    progress: Progress,
    task: TaskID,
) -> None:
    """Process a single package."""
    # Fetch stars
    stars = 0
    if pkg.repo_url:
        stars = await get_repo_stars(pkg.repo_url)

    # Score
    pkg_downloads = downloads_map.get(pkg.name.lower(), 0)
    candidate = score_candidate(pkg, vuln_index, downloads=pkg_downloads, repo_stars=stars)
    candidates.append(candidate)
    progress.update(task, advance=1)


async def run_pipeline(
    pypi_json: Optional[Path] = None,
    packages: Optional[str] = None,
    osv_dump: Optional[Path] = None,
    downloads_csv: Optional[Path] = None,
    limit: int = 100,
    include_cli: bool = True,
    include_ml: bool = True,
    include_dev: bool = True,
    out: Path = Path("top_candidates.json"),
) -> None:
    """Orchestrate the candidate finding pipeline."""

    # 1. Load OSV index
    vuln_index = VulnerabilityIndex()
    if osv_dump and osv_dump.exists():
        console.print(f"[bold blue]Loading OSV index from {osv_dump}...[/bold blue]")
        vuln_index = load_osv_index(osv_dump)
    else:
        console.print("[yellow]Warning: No OSV dump provided or found. Skipping vulnerability analysis.[/yellow]")

    # 2. Load downloads data if provided
    downloads_map: dict[str, int] = {}
    if downloads_csv and downloads_csv.exists():
        console.print(f"[bold blue]Loading downloads from {downloads_csv}...[/bold blue]")
        with downloads_csv.open("r") as f:
            for line in f:
                parts = line.strip().split(",")
                if len(parts) >= 2:
                    name, count = parts[0], parts[1]
                    try:
                        downloads_map[name.lower()] = int(count)
                    except ValueError:
                        continue

    # 3. Stream and process packages
    candidates: list[CandidateRecord] = []

    with Progress() as progress:
        task = progress.add_task("[green]Processing packages...", total=None)

        # Determine source and stream
        if packages:
            pkg_names = [p.strip() for p in packages.split(",") if p.strip()]
            async for pkg in fetch_packages_from_api(pkg_names):
                if not is_target_category(pkg, include_cli, include_ml, include_dev):
                    continue
                await _process_package(pkg, vuln_index, downloads_map, candidates, progress, task)
        elif pypi_json and pypi_json.exists():
            for pkg in stream_packages_from_jsonl(pypi_json):
                if not is_target_category(pkg, include_cli, include_ml, include_dev):
                    continue
                await _process_package(pkg, vuln_index, downloads_map, candidates, progress, task)
        else:
            console.print("[bold red]Error: Either --pypi-json or --packages must be provided.[/bold red]")
            raise typer.Exit(1)

    # 4. Sort and output

    top_candidates = candidates[:limit]

    console.print(f"[bold green]Writing top {len(top_candidates)} candidates to {out}[/bold green]")
    with out.open("w") as f:
        json.dump([c.model_dump() for c in top_candidates], f, indent=2)


@app.command()
def main(
    pypi_json: Optional[Path] = typer.Option(None, help="Path to PyPI bulk JSONL file"),
    packages: Optional[str] = typer.Option(None, help="Comma-separated package names for live API fetch"),
    osv_dump: Path = typer.Option(..., help="Path to OSV PyPI vulnerability ZIP dump"),
    downloads_csv: Optional[Path] = typer.Option(None, help="Path to CSV with package downloads (name,count)"),
    limit: int = typer.Option(100, help="Max number of candidates to output"),
    include_cli: bool = typer.Option(True, help="Include CLI tools"),
    include_ml: bool = typer.Option(True, help="Include ML/AI projects"),
    include_dev: bool = typer.Option(True, help="Include Dev tools"),
    out: Path = typer.Option("top_candidates.json", help="Output file path"),
) -> None:
    """Find candidate Python projects for security audit."""
    asyncio.run(
        run_pipeline(
            pypi_json=pypi_json,
            packages=packages,
            osv_dump=osv_dump,
            downloads_csv=downloads_csv,
            limit=limit,
            include_cli=include_cli,
            include_ml=include_ml,
            include_dev=include_dev,
            out=out,
        )
    )


if __name__ == "__main__":
    app()
