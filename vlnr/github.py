import asyncio
import json
import os
import time
from pathlib import Path
from urllib.parse import quote

import aiohttp

_CACHE_FILE = Path(".gh_stars_cache.json")
_STARS_CACHE: dict[str, int] = {}
_API_SEMAPHORE = asyncio.Semaphore(3)


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


async def get_repo_stars(repo_url: str) -> int | None:
    """
    Fetch star count from GitHub or GitLab API.
    Returns None for unsupported hosts or failure.
    """
    if not repo_url:
        return None

    repo_url_lower = repo_url.lower()
    is_github = "github.com" in repo_url_lower
    is_gitlab = "gitlab.com" in repo_url_lower

    if not is_github and not is_gitlab:
        return None

    if repo_url in _STARS_CACHE:
        return _STARS_CACHE[repo_url]

    # Extract owner/repo from URL
    # For GitLab, we need the full path after gitlab.com/
    path_after_host = repo_url_lower.split("github.com/" if is_github else "gitlab.com/")[1]
    path_after_host = path_after_host.rstrip("/")

    if is_github:
        parts = path_after_host.split("/")
        if len(parts) < 2:
            return None
        owner = parts[0]
        repo = parts[1]
        api_url = f"https://api.github.com/repos/{owner}/{repo}"
        headers = {"Accept": "application/vnd.github.v3+json", "User-Agent": "vlnr-candidate-finder"}
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"token {token}"
        star_key = "stargazers_count"
    else:  # is_gitlab
        # GitLab API uses project ID or URL-encoded path
        project_path = quote(path_after_host, safe="")
        api_url = f"https://gitlab.com/api/v4/projects/{project_path}"
        headers = {"User-Agent": "vlnr-candidate-finder"}
        token = os.environ.get("GITLAB_TOKEN")
        if token:
            headers["PRIVATE-TOKEN"] = token
        star_key = "star_count"

    async with _API_SEMAPHORE:
        try:
            async with aiohttp.ClientSession() as session:
                while True:
                    async with session.get(api_url, headers=headers) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            stars = int(data.get(star_key, 0))
                            _STARS_CACHE[repo_url] = stars
                            _save_cache()
                            return stars

                        if resp.status in (403, 429):
                            # Rate limit handling (common patterns)
                            retry_after = resp.headers.get("Retry-After")
                            if retry_after:
                                await asyncio.sleep(int(retry_after) + 1)
                                continue

                            if is_github:
                                reset_time = resp.headers.get("X-RateLimit-Reset")
                                remaining = resp.headers.get("X-RateLimit-Remaining")
                                if remaining == "0" and reset_time:
                                    sleep_time = int(reset_time) - int(time.time()) + 1
                                    if 0 < sleep_time < 60:
                                        await asyncio.sleep(sleep_time)
                                        continue
                                    else:
                                        return None

                        return None
        except aiohttp.ClientError, ValueError, KeyError:
            return None
