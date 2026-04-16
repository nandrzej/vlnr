import json
import pytest
from pathlib import Path
from vlnr.pypi import extract_repo_url, stream_packages_from_jsonl, fetch_packages_from_api
from vlnr.models import PackageInfo

def test_extract_repo_url():
    urls = {
        "Homepage": "https://github.com/user/project",
        "Source": "https://github.com/user/project-source",
    }
    assert extract_repo_url(urls) == "https://github.com/user/project-source"
    
    urls = {"Homepage": "https://gitlab.com/user/project"}
    assert extract_repo_url(urls) == "https://gitlab.com/user/project"

    urls = {"Documentation": "https://docs.io"}
    assert extract_repo_url(urls) is None

def test_stream_packages_from_jsonl(tmp_path):
    p = tmp_path / "pypi.jsonl"
    pkg1 = {"name": "pkg1", "version": "1.0", "project_urls": {"Source": "https://github.com/a/b"}}
    pkg2 = {"name": "pkg2", "version": "2.0"}
    
    with open(p, "w") as f:
        f.write(json.dumps(pkg1) + "\n")
        f.write(json.dumps({"info": pkg2}) + "\n")
        
    pkgs = list(stream_packages_from_jsonl(p))
    assert len(pkgs) == 2
    assert pkgs[0].name == "pkg1"
    assert pkgs[0].repo_url == "https://github.com/a/b"
    assert pkgs[1].name == "pkg2"

@pytest.mark.asyncio
async def test_fetch_packages_from_api(monkeypatch):
    class MockResponse:
        def __init__(self, data, status=200):
            self.data = data
            self.status = status
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def json(self): return self.data

    class MockSession:
        def get(self, url):
            if "exists" in url:
                return MockResponse({"info": {"name": "exists", "version": "1.0"}})
            return MockResponse({}, status=404)
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass

    monkeypatch.setattr("aiohttp.ClientSession", lambda: MockSession())
    async def mock_sleep(x): pass
    monkeypatch.setattr("asyncio.sleep", mock_sleep)
    
    pkgs = []
    async for pkg in fetch_packages_from_api(["exists", "missing"]):
        pkgs.append(pkg)
        
    assert len(pkgs) == 1
    assert pkgs[0].name == "exists"
