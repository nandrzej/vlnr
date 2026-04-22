import json
import time
from pathlib import Path

import aiohttp
from rich.console import Console

console = Console()

TOP_PYPI_URL = "https://hugovk.dev/top-pypi-packages/top-pypi-packages-30-days.json"
CACHE_DIR = Path.home() / ".cache" / "vlnr"


async def fetch_top_packages() -> dict[str, int]:
    """
    Fetch top 15k packages by downloads from hugovk.dev.
    Returns mapping of package_name -> monthly_downloads.
    """
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_file = CACHE_DIR / "top_pypi_packages.json"

    # Check cache (1 day TTL)
    if cache_file.exists() and (time.time() - cache_file.stat().st_mtime) < 86400:
        try:
            with cache_file.open("r") as f:
                data = json.load(f)
                return {item["project"].lower(): item.get("download_count", 0) for item in data.get("rows", [])}
        except json.JSONDecodeError, KeyError:
            pass

    console.print("[bold blue]Fetching popularity data from hugovk.dev...[/bold blue]")
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(TOP_PYPI_URL) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    data = json.loads(content)
                    # Cache it
                    with cache_file.open("w") as f:
                        f.write(content)
                    return {item["project"].lower(): item.get("download_count", 0) for item in data.get("rows", [])}
                else:
                    console.print(f"[yellow]Warning: Failed to fetch popularity data (HTTP {resp.status}).[/yellow]")
        except Exception as e:
            console.print(f"[yellow]Warning: Failed to fetch popularity data: {e}[/yellow]")

    return {}
