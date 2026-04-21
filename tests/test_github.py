import pytest
from typing import Any, Dict, List, Optional, Generator
from vlnr import github


@pytest.fixture
def clean_gh_cache(monkeypatch: pytest.MonkeyPatch) -> Generator[None, None, None]:
    """Ensure cache is empty and file removed before/after tests."""
    # Reset internal state
    monkeypatch.setattr(github, "_STARS_CACHE", {})
    if github._CACHE_FILE.exists():
        github._CACHE_FILE.unlink()
    yield
    if github._CACHE_FILE.exists():
        github._CACHE_FILE.unlink()


@pytest.mark.asyncio
async def test_get_repo_stars_caching(monkeypatch: pytest.MonkeyPatch, clean_gh_cache: Any) -> None:
    # Mock aiohttp
    call_count = 0

    class MockResponse:
        def __init__(self, data: Dict[str, Any], status: int = 200) -> None:
            self.data = data
            self.status = status

        async def __aenter__(self) -> "MockResponse":
            return self

        async def __aexit__(self, *args: Any) -> None:
            pass

        async def json(self) -> Dict[str, Any]:
            return self.data

    class MockSession:
        def get(self, url: str, headers: Optional[Dict[str, str]] = None) -> MockResponse:
            nonlocal call_count
            call_count += 1
            return MockResponse({"stargazers_count": 100})

        async def __aenter__(self) -> "MockSession":
            return self

        async def __aexit__(self, *args: Any) -> None:
            pass

    monkeypatch.setattr("aiohttp.ClientSession", lambda: MockSession())

    url = "https://github.com/owner/repo"

    # First call: should fetch and cache
    stars = await github.get_repo_stars(url)
    assert stars == 100
    assert call_count == 1
    assert github._CACHE_FILE.exists()

    # Second call: should use cache
    stars2 = await github.get_repo_stars(url)
    assert stars2 == 100
    assert call_count == 1


@pytest.mark.asyncio
async def test_get_repo_stars_rate_limit(monkeypatch: pytest.MonkeyPatch, clean_gh_cache: Any) -> None:
    # Mock aiohttp to return 429 once then 200
    responses: List[Dict[str, Any]] = [
        {"status": 429, "headers": {"Retry-After": "1"}},
        {"status": 200, "data": {"stargazers_count": 50}},
    ]

    class MockResponse:
        def __init__(self, r: Dict[str, Any]) -> None:
            self.status = r["status"]
            self.headers = r.get("headers", {})
            self._data = r.get("data")

        async def __aenter__(self) -> "MockResponse":
            return self

        async def __aexit__(self, *args: Any) -> None:
            pass

        async def json(self) -> Any:
            return self._data

    class MockSession:
        def __init__(self) -> None:
            self.idx = 0

        def get(self, url: str, headers: Optional[Dict[str, str]] = None) -> MockResponse:
            resp = MockResponse(responses[self.idx])
            self.idx += 1
            return resp

        async def __aenter__(self) -> "MockSession":
            return self

        async def __aexit__(self, *args: Any) -> None:
            pass

    monkeypatch.setattr("aiohttp.ClientSession", lambda: MockSession())

    # Mock sleep to avoid waiting
    sleep_calls: List[float] = []

    async def mock_sleep(seconds: float) -> None:
        sleep_calls.append(seconds)

    monkeypatch.setattr("asyncio.sleep", mock_sleep)

    url = "https://github.com/owner/rate-limited"
    stars = await github.get_repo_stars(url)

    assert stars == 50
    assert len(sleep_calls) == 1
    assert sleep_calls[0] == 2  # Retry-After (1) + 1


@pytest.mark.asyncio
async def test_get_repo_stars_unsupported_host() -> None:
    """Non-GitHub/GitLab URL returns None"""
    url = "https://bitbucket.org/owner/repo"
    stars = await github.get_repo_stars(url)
    assert stars is None


@pytest.mark.asyncio
async def test_get_repo_stars_gitlab(monkeypatch: pytest.MonkeyPatch, clean_gh_cache: Any) -> None:
    """GitLab URL fetches stars via GitLab API"""

    class MockResponse:
        async def __aenter__(self) -> "MockResponse":
            return self

        async def __aexit__(self, *args: Any) -> None:
            pass

        async def json(self) -> Dict[str, Any]:
            return {"star_count": 42}

        @property
        def status(self) -> int:
            return 200

    class MockSession:
        def get(self, url: str, headers: Optional[Dict[str, str]] = None) -> MockResponse:
            assert "gitlab.com/api/v4/projects" in url
            return MockResponse()

        async def __aenter__(self) -> "MockSession":
            return self

        async def __aexit__(self, *args: Any) -> None:
            pass

    monkeypatch.setattr("aiohttp.ClientSession", lambda: MockSession())

    url = "https://gitlab.com/owner/repo"
    stars = await github.get_repo_stars(url)
    assert stars == 42
