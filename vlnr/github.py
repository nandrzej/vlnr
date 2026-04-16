import os
from functools import lru_cache

import aiohttp


@lru_cache(maxsize=5000)
async def get_repo_stars(repo_url: str) -> int:
    """
    Fetch star count from GitHub API.
    Requires GITHUB_TOKEN env var for higher limits.
    Returns 0 on failure.
    """
    if not repo_url or "github.com" not in repo_url.lower():
        return 0

    # Extract owner/repo from URL
    # https://github.com/owner/repo[/...]
    parts = repo_url.rstrip("/").split("/")
    if len(parts) < 5:
        return 0

    owner = parts[3]
    repo = parts[4]

    api_url = f"https://api.github.com/repos/{owner}/{repo}"

    headers = {"Accept": "application/vnd.github.v3+json", "User-Agent": "vlnr-candidate-finder"}

    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(api_url, headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return int(data.get("stargazers_count", 0))
                return 0
    except aiohttp.ClientError, ValueError, KeyError:
        return 0
