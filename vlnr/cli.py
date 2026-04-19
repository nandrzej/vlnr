import asyncio
import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, TaskID

from vlnr.data import fetch_top_packages
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
    downloads_map: Optional[dict[str, int]],
    deps_map: Optional[dict[str, int]],
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
    pkg_downloads = 0
    if downloads_map is not None:
        pkg_downloads = downloads_map.get(pkg.name.lower(), 0)

    candidate = score_candidate(pkg, vuln_index, downloads=pkg_downloads, repo_stars=stars, dependency_map=deps_map)
    candidates.append(candidate)
    progress.update(task, advance=1)


async def run_pipeline(
    pypi_json: Optional[Path] = None,
    packages: Optional[str] = None,
    osv_dump: Optional[Path] = None,
    pypa_repo: Optional[Path] = None,
    downloads_csv: Optional[Path] = None,
    deps_csv: Optional[Path] = None,
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
        console.print("[yellow]Warning: No OSV dump provided or found. Skipping OSV vulnerability analysis.[/yellow]")

    if pypa_repo and pypa_repo.exists():
        from vlnr.osv import load_pypa_advisory_db

        console.print(f"[bold blue]Loading PyPA advisories from {pypa_repo}...[/bold blue]")
        load_pypa_advisory_db(pypa_repo, vuln_index)

    # 2. Load downloads and deps data if provided
    downloads_map: Optional[dict[str, int]] = None
    if downloads_csv and downloads_csv.exists():
        downloads_map = {}
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
    elif not downloads_csv:
        # Auto-fetch if no CSV provided
        downloads_map = await fetch_top_packages()
    else:
        console.print("[yellow]Warning: Downloads CSV provided but not found. Download scores will be 0.0.[/yellow]")

    deps_map: Optional[dict[str, int]] = None
    if deps_csv and deps_csv.exists():
        deps_map = {}
        console.print(f"[bold blue]Loading dependencies from {deps_csv}...[/bold blue]")
        with deps_csv.open("r") as f:
            for line in f:
                parts = line.strip().split(",")
                if len(parts) >= 2:
                    name, count = parts[0], parts[1]
                    try:
                        deps_map[name.lower()] = int(count)
                    except ValueError:
                        continue
    else:
        console.print("[yellow]Warning: No dependencies CSV provided. Centrality scores will be 0.5.[/yellow]")

    # 2.5 Check GITHUB_TOKEN
    import os

    if not os.environ.get("GITHUB_TOKEN"):
        console.print(
            "[yellow]Warning: GITHUB_TOKEN not set. GitHub API requests will be heavily rate-limited.[/yellow]"
        )

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
                await _process_package(pkg, vuln_index, downloads_map, deps_map, candidates, progress, task)
        elif pypi_json and pypi_json.exists():
            tasks = []
            # We need to buffer more than limit to have something to sort
            buffer_limit = limit * 10
            for pkg in stream_packages_from_jsonl(pypi_json):
                if not is_target_category(pkg, include_cli, include_ml, include_dev):
                    continue

                tasks.append(_process_package(pkg, vuln_index, downloads_map, deps_map, candidates, progress, task))
                if len(tasks) >= 50:
                    await asyncio.gather(*tasks)
                    tasks = []

                if len(candidates) >= buffer_limit:
                    break

            if tasks and len(candidates) < buffer_limit:
                await asyncio.gather(*tasks)
        else:
            console.print("[bold red]Error: Either --pypi-json or --packages must be provided.[/bold red]")
            raise typer.Exit(1)

    # 4. Sort and output
    candidates.sort(key=lambda x: x.candidate_score, reverse=True)
    top_candidates = candidates[:limit]

    console.print(f"[bold green]Writing top {len(top_candidates)} candidates to {out}[/bold green]")
    with out.open("w") as f:
        json.dump([c.model_dump() for c in top_candidates], f, indent=2)


@app.command()
def main(
    pypi_json: Optional[Path] = typer.Option(None, help="Path to PyPI bulk JSONL file"),
    packages: Optional[str] = typer.Option(None, help="Comma-separated package names for live API fetch"),
    osv_dump: Path = typer.Option(..., help="Path to OSV PyPI vulnerability ZIP dump"),
    pypa_repo: Optional[Path] = typer.Option(None, help="Path to local clone of pypa/advisory-database"),
    downloads_csv: Optional[Path] = typer.Option(None, help="Path to CSV with package downloads (name,count)"),
    deps_csv: Optional[Path] = typer.Option(None, help="Path to CSV with package dependents (name,count)"),
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
            pypa_repo=pypa_repo,
            downloads_csv=downloads_csv,
            deps_csv=deps_csv,
            limit=limit,
            include_cli=include_cli,
            include_ml=include_ml,
            include_dev=include_dev,
            out=out,
        )
    )


if __name__ == "__main__":
    app()
