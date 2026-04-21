import asyncio
import json
import os
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress

from vlnr.data import fetch_top_packages
from vlnr.filters import is_target_category
from vlnr.github import get_repo_stars
from vlnr.models import CandidateRecord, PackageInfo, VulnerabilityIndex
from vlnr.llm import LLMClient
from vlnr.osv import load_osv_index, load_epss_scores
from vlnr.pypi import fetch_packages_from_api, stream_packages_from_jsonl
from vlnr.scorer import score_candidate, build_reverse_dependency_graph, normalize_log

app = typer.Typer(help="Vulnerability-aware Python Project Finder")
console = Console()


async def run_pipeline(
    pypi_json: Optional[Path] = None,
    packages: Optional[str] = None,
    osv_dump: Optional[Path] = None,
    pypa_repo: Optional[Path] = None,
    downloads_csv: Optional[Path] = None,
    limit: int = 100,
    include_cli: bool = True,
    include_ml: bool = True,
    include_dev: bool = True,
    llm_discovery: bool = False,
    mode: str = "discovery",
    out: Path = Path("top_candidates.json"),
) -> None:
    """Orchestrate the candidate finding pipeline."""

    # 1. Load OSV index and EPSS scores
    epss_scores = {}
    cache_dir = Path(".vlnr_cache")
    try:
        console.print("[bold blue]Loading EPSS scores...[/bold blue]")
        epss_scores = load_epss_scores(cache_dir)
    except Exception as e:
        console.print(f"[yellow]Warning: Failed to load EPSS scores: {e}[/yellow]")

    vuln_index = VulnerabilityIndex()
    if osv_dump and osv_dump.exists():
        console.print(f"[bold blue]Loading OSV index from {osv_dump}...[/bold blue]")
        vuln_index = load_osv_index(osv_dump, epss_scores=epss_scores)
    else:
        console.print("[yellow]Warning: No OSV dump provided or found. Skipping OSV vulnerability analysis.[/yellow]")

    if pypa_repo and pypa_repo.exists():
        console.print(f"[bold blue]Loading PyPA advisories from {pypa_repo}...[/bold blue]")
        # Note: load_pypa_advisory_db was removed in OSV refactor as OSV covers it
        # and load_pypa_advisory_db was not updated for the new schema.
        # It is deprecated in favor of OSV dump.

    # 1.5 Setup LLM Client if discovery enabled
    llm_client: Optional[LLMClient] = None
    if llm_discovery:
        try:
            llm_client = LLMClient()
            from vlnr.llm import LLMTier

            model_name = LLMTier.TIER_3.value
            console.print(f"[bold blue]LLM Discovery enabled. Using {model_name} for intent scoring.[/bold blue]")
        except Exception as e:
            console.print(f"[bold red]Error initializing LLM client: {e}. Proceeding without LLM.[/bold red]")
            llm_discovery = False

    # 2. Load downloads data
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
        downloads_map = await fetch_top_packages()

    # 2.5 Check tokens
    if not os.environ.get("GITHUB_TOKEN"):
        console.print(
            "[yellow]Warning: GITHUB_TOKEN not set. GitHub API requests will be heavily rate-limited.[/yellow]"
        )

    # 3. Stream and process packages (Pass 1: Discovery & Graph building)
    discovered_pkgs: list[PackageInfo] = []

    with Progress() as progress:
        scan_task = progress.add_task("[green]Scanning packages...", total=None)

        if packages:
            pkg_names = [p.strip() for p in packages.split(",") if p.strip()]
            async for pkg in fetch_packages_from_api(pkg_names):
                if is_target_category(pkg, include_cli, include_ml, include_dev):
                    discovered_pkgs.append(pkg)
                    progress.update(
                        scan_task, advance=1, description=f"[green]Scanning: {len(discovered_pkgs)} pkgs found"
                    )
        elif pypi_json and pypi_json.exists():
            for pkg in stream_packages_from_jsonl(pypi_json):
                if is_target_category(pkg, include_cli, include_ml, include_dev):
                    discovered_pkgs.append(pkg)
                    progress.update(
                        scan_task, advance=1, description=f"[green]Scanning: {len(discovered_pkgs)} pkgs found"
                    )
        else:
            console.print("[bold red]Error: Either --pypi-json or --packages must be provided.[/bold red]")
            raise typer.Exit(1)

        if not discovered_pkgs:
            console.print("[yellow]No candidates found.[/yellow]")
            return

        # Pass 2: Build dependency graph and preliminary score
        console.print("[bold blue]Building reverse dependency graph...[/bold blue]")
        dep_graph = build_reverse_dependency_graph(discovered_pkgs)

        discovered_candidates: list[tuple[PackageInfo, CandidateRecord]] = []
        scoring_task = progress.add_task("[blue]Scoring candidates...", total=len(discovered_pkgs))

        for pkg in discovered_pkgs:
            pkg_downloads = downloads_map.get(pkg.name.lower(), 0) if downloads_map else 0
            deps_count = dep_graph.get(pkg.name.lower(), 0)
            centrality = normalize_log(float(deps_count), 10_000.0)

            # Initial score with stars=None
            candidate = score_candidate(
                pkg,
                vuln_index,
                mode=mode,  # type: ignore
                downloads=pkg_downloads,
                repo_stars=None,
                centrality=centrality,
                llm_client=llm_client if llm_discovery else None,
            )
            discovered_candidates.append((pkg, candidate))
            progress.update(scoring_task, advance=1)

        # 4. Refinement Pass (Pass 3: Fetch stars for top buffer)
        discovered_candidates.sort(key=lambda x: x[1].candidate_score, reverse=True)
        refine_buffer = min(len(discovered_candidates), max(limit * 3, 500))
        to_refine = discovered_candidates[:refine_buffer]

        console.print(f"[bold blue]Refining top {len(to_refine)} candidates (fetching stars)...[/bold blue]")
        refine_task = progress.add_task("[magenta]Refining...", total=len(to_refine))

        final_candidates: list[CandidateRecord] = []
        batch_size = 20
        for i in range(0, len(to_refine), batch_size):
            batch = to_refine[i : i + batch_size]

            async def process_refined(item: tuple[PackageInfo, CandidateRecord]) -> CandidateRecord:
                pkg, _ = item
                stars = None
                if pkg.repo_url:
                    stars = await get_repo_stars(pkg.repo_url)

                pkg_downloads = downloads_map.get(pkg.name.lower(), 0) if downloads_map else 0
                deps_count = dep_graph.get(pkg.name.lower(), 0)
                centrality = normalize_log(float(deps_count), 10_000.0)

                # Re-score with stars
                candidate = score_candidate(
                    pkg,
                    vuln_index,
                    mode=mode,  # type: ignore
                    downloads=pkg_downloads,
                    repo_stars=stars,
                    centrality=centrality,
                    llm_client=llm_client if llm_discovery else None,
                )
                progress.update(refine_task, advance=1)
                return candidate

            results = await asyncio.gather(*[process_refined(item) for item in batch])
            final_candidates.extend(results)

    # Final sort and output
    final_candidates.sort(key=lambda x: x.candidate_score, reverse=True)
    top_candidates = final_candidates[:limit]

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
    limit: int = typer.Option(100, help="Max number of candidates to output"),
    include_cli: bool = typer.Option(True, help="Include CLI tools"),
    include_ml: bool = typer.Option(True, help="Include ML/AI projects"),
    include_dev: bool = typer.Option(True, help="Include Dev tools"),
    llm_discovery: bool = typer.Option(False, "--llm-discovery", help="Use LLM to score package intent"),
    mode: str = typer.Option("discovery", help="Scoring mode: discovery or triage"),
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
            limit=limit,
            include_cli=include_cli,
            include_ml=include_ml,
            include_dev=include_dev,
            llm_discovery=llm_discovery,
            mode=mode,
            out=out,
        )
    )


if __name__ == "__main__":
    app()
