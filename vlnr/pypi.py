import asyncio
import json
from collections.abc import AsyncIterator, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

import aiohttp
from pydantic import ValidationError

from vlnr.models import PackageInfo


def stream_packages_from_jsonl(path: Path) -> Iterator[PackageInfo]:
    """Stream packages from bulk JSON. Handles both JSONL and large JSON arrays."""
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped in ("[", "]"):
                continue

            # Handle trailing comma in JSON arrays
            if stripped.endswith(","):
                stripped = stripped[:-1]

            try:
                data = json.loads(stripped)
                info_data = data.get("info", data)

                # Pre-process info_data before pydantic validation
                if not isinstance(info_data.get("project_urls"), dict):
                    info_data["project_urls"] = {}
                if info_data.get("classifiers") is None:
                    info_data["classifiers"] = []
                if info_data.get("summary") is None:
                    info_data["summary"] = ""

                # Try to get upload_time from info or from urls list
                upload_time_str = info_data.get("upload_time")
                if not upload_time_str:
                    urls = data.get("urls", [])
                    if urls:
                        # Find the latest upload_time in the urls list
                        times = [u.get("upload_time") for u in urls if u.get("upload_time")]
                        if times:
                            upload_time_str = max(times)

                if isinstance(upload_time_str, str):
                    try:
                        # PyPI typically uses ISO format
                        info_data["upload_time"] = datetime.fromisoformat(upload_time_str.replace("Z", "+00:00"))
                    except ValueError:
                        pass

                pkg = PackageInfo(**info_data)
                pkg.repo_url = extract_repo_url(pkg.project_urls)
                if "console_scripts" in info_data:
                    pkg.console_scripts = info_data["console_scripts"]

                # Extract requires_dist
                rdist = info_data.get("requires_dist")
                if isinstance(rdist, list):
                    pkg.requires_dist = [str(r) for r in rdist if r]

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
                    # PyPI API doesn't have upload_time in info, but it is in urls or releases
                    upload_time_str = None
                    urls = data.get("urls", [])
                    if urls:
                        times = [u.get("upload_time") for u in urls if u.get("upload_time")]
                        if times:
                            upload_time_str = max(times)

                    if not upload_time_str and "releases" in data and info.get("version") in data["releases"]:
                        rel_assets = data["releases"][info["version"]]
                        if rel_assets:
                            times = [r.get("upload_time") for r in rel_assets if r.get("upload_time")]
                            if times:
                                upload_time_str = max(times)

                    if upload_time_str:
                        info["upload_time"] = upload_time_str

                    pkg = PackageInfo(**info)
                    pkg.repo_url = extract_repo_url(pkg.project_urls)

                    # Entry points are in releases/latest_version/entry_points
                    # or sometimes in a specific field
                    entry_points = info.get("entry_points")
                    if isinstance(entry_points, dict):
                        pkg.console_scripts = list(entry_points.get("console_scripts", {}).keys())

                    rdist = info.get("requires_dist")
                    if isinstance(rdist, list):
                        pkg.requires_dist = [str(r) for r in rdist if r]

                    yield pkg
                except ValidationError:
                    continue
            await asyncio.sleep(0.1)  # Rate limit: 10 req/sec


def extract_repo_url(project_urls: Any) -> str | None:
    """Priority: Source > Code > Homepage. Only return GitHub/GitLab URLs."""
    if not isinstance(project_urls, dict):
        return None

    # Normalise keys to lowercase, ensuring values are strings
    urls = {str(k).lower(): str(v) for k, v in project_urls.items() if v}

    priority_keys = ["source", "code", "homepage", "repository"]

    for key in priority_keys:
        url = urls.get(key)
        if url and any(domain in url.lower() for domain in ["github.com", "gitlab.com"]):
            # Strip trailing whitespace, trailing slash, and then .git suffix
            normalized = url.strip().rstrip("/")
            if normalized.lower().endswith(".git"):
                normalized = normalized[:-4]
            return normalized.rstrip("/")

    return None
