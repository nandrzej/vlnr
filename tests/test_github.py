import pytest
from vlnr import github


@pytest.fixture
def clean_gh_cache(monkeypatch):
    """Ensure cache is empty and file removed before/after tests."""
    # Reset internal state
    monkeypatch.setattr(github, "_STARS_CACHE", {})
    if github._CACHE_FILE.exists():
        github._CACHE_FILE.unlink()
    yield
    if github._CACHE_FILE.exists():
        github._CACHE_FILE.unlink()


@pytest.mark.asyncio
async def test_get_repo_stars_caching(monkeypatch, clean_gh_cache):
    # Mock aiohttp
    call_count = 0

    class MockResponse:
        def __init__(self, data, status=200):
            self.data = data
            self.status = status

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def json(self):
            return self.data

    class MockSession:
        def get(self, url, headers=None):
            nonlocal call_count
            call_count += 1
            return MockResponse({"stargazers_count": 100})

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
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
async def test_get_repo_stars_rate_limit(monkeypatch, clean_gh_cache):
    # Mock aiohttp to return 429 once then 200
    responses = [{"status": 429, "headers": {"Retry-After": "1"}}, {"status": 200, "data": {"stargazers_count": 50}}]

    class MockResponse:
        def __init__(self, r):
            self.status = r["status"]
            self.headers = r.get("headers", {})
            self._data = r.get("data")

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def json(self):
            return self._data

    class MockSession:
        def __init__(self):
            self.idx = 0

        def get(self, url, headers=None):
            resp = MockResponse(responses[self.idx])
            self.idx += 1
            return resp

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    monkeypatch.setattr("aiohttp.ClientSession", lambda: MockSession())

    # Mock sleep to avoid waiting
    sleep_calls = []

    async def mock_sleep(seconds):
        sleep_calls.append(seconds)

    monkeypatch.setattr("asyncio.sleep", mock_sleep)

    url = "https://github.com/owner/rate-limited"
    stars = await github.get_repo_stars(url)

    assert stars == 50
    assert len(sleep_calls) == 1
    assert sleep_calls[0] == 2  # Retry-After (1) + 1
