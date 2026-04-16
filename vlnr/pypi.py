import asyncio
import json
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import aiohttp
from pydantic import ValidationError

from vlnr.models import PackageInfo


def stream_packages_from_jsonl(path: Path) -> Iterator[PackageInfo]:
    """Stream packages from bulk JSONL."""
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                # Bulk JSONL format varies; assuming a common nested structure or flat
                # If it's the BigQuery dump format, it might be nested
                info_data = data.get("info", data)
                pkg = PackageInfo(**info_data)

                # Extract repo_url and console_scripts
                pkg.repo_url = extract_repo_url(pkg.project_urls)
                # Console scripts might be in release data which isn't always in bulk JSON
                # But we'll try to get them if available
                if "console_scripts" in info_data:
                    pkg.console_scripts = info_data["console_scripts"]

                yield pkg
            except json.JSONDecodeError, ValidationError:
                continue


async def fetch_packages_from_api(names: list[str]) -> AsyncIterator[PackageInfo]:
    """Fetch specific packages from live PyPI API."""
    async with aiohttp.ClientSession() as session:
        for name in names:
            url = f"https://pypi.org/pypi/{name}/json"
            async with session.get(url) as resp:
                if resp.status != 200:
                    continue
                data = await resp.json()
                try:
                    info = data.get("info", {})
                    pkg = PackageInfo(**info)
                    pkg.repo_url = extract_repo_url(pkg.project_urls)

                    # Entry points are in releases/latest_version/entry_points
                    # or sometimes in a specific field
                    entry_points = info.get("entry_points")
                    if isinstance(entry_points, dict):
                        pkg.console_scripts = list(entry_points.get("console_scripts", {}).keys())

                    yield pkg
                except ValidationError:
                    continue
            await asyncio.sleep(0.1)  # Rate limit: 10 req/sec


def extract_repo_url(project_urls: dict[str, str] | None) -> str | None:
    """Priority: Source > Code > Homepage. Only return GitHub/GitLab URLs."""
    if not project_urls:
        return None

    # Normalise keys to lowercase
    urls = {k.lower(): v for k, v in project_urls.items() if v}

    priority_keys = ["source", "code", "homepage", "repository"]

    for key in priority_keys:
        url = urls.get(key)
        if url and any(domain in url.lower() for domain in ["github.com", "gitlab.com"]):
            # Strip trailing .git and whitespace
            return url.strip().removesuffix(".git").rstrip("/")

    return None
