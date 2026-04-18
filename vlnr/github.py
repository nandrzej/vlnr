import asyncio
import json
import os
import time
from pathlib import Path

import aiohttp

_CACHE_FILE = Path(".gh_stars_cache.json")
_STARS_CACHE: dict[str, int] = {}
_GITHUB_SEMAPHORE = asyncio.Semaphore(3)


def _load_cache() -> None:
    global _STARS_CACHE
    if _CACHE_FILE.exists():
        try:
            with _CACHE_FILE.open("r") as f:
                _STARS_CACHE = json.load(f)
        except json.JSONDecodeError, IOError:
            _STARS_CACHE = {}


def _save_cache() -> None:
    try:
        with _CACHE_FILE.open("w") as f:
            json.dump(_STARS_CACHE, f)
    except IOError:
        pass


# Initial load
_load_cache()


async def get_repo_stars(repo_url: str) -> int:
    """
    Fetch star count from GitHub API.
    Requires GITHUB_TOKEN env var for higher limits.
    Returns 0 on failure.
    """
    if not repo_url or "github.com" not in repo_url.lower():
        return 0

    if repo_url in _STARS_CACHE:
        return _STARS_CACHE[repo_url]

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

    async with _GITHUB_SEMAPHORE:
        try:
            async with aiohttp.ClientSession() as session:
                while True:
                    async with session.get(api_url, headers=headers) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            stars = int(data.get("stargazers_count", 0))
                            _STARS_CACHE[repo_url] = stars
                            _save_cache()
                            return stars

                        if resp.status in (403, 429):
                            # Rate limit handling
                            reset_time = resp.headers.get("X-RateLimit-Reset")
                            remaining = resp.headers.get("X-RateLimit-Remaining")

                            if remaining == "0" and reset_time:
                                sleep_time = int(reset_time) - int(time.time()) + 1
                                if sleep_time > 0:
                                    # Don't sleep for too long in a CLI tool, but honor it if reasonable
                                    if sleep_time < 60:
                                        await asyncio.sleep(sleep_time)
                                        continue
                                    else:
                                        return 0

                            # Secondary rate limit / abuse
                            retry_after = resp.headers.get("Retry-After")
                            if retry_after:
                                await asyncio.sleep(int(retry_after) + 1)
                                continue

                        return 0
        except aiohttp.ClientError, ValueError, KeyError:
            return 0
