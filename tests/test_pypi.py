from pathlib import Path
import typing
import json
import pytest
from vlnr.pypi import extract_repo_url, stream_packages_from_jsonl, fetch_packages_from_api


def test_extract_repo_url() -> None:
    urls = {
        "Homepage": "https://github.com/user/project",
        "Source": "https://github.com/user/project-source",
    }
    assert extract_repo_url(urls) == "https://github.com/user/project-source"

    urls = {
        "Homepage": "https://gitlab.com/user/project",
    }
    assert extract_repo_url(urls) == "https://gitlab.com/user/project"

    urls = {
        "Documentation": "https://docs.io",
    }
    assert extract_repo_url(urls) is None

    # Test with .git suffix and trailing slash
    urls = {
        "Repository": "https://github.com/user/project.git/",
    }
    assert extract_repo_url(urls) == "https://github.com/user/project"

    # Test Case Insensitivity
    urls = {
        "source": "https://GITHUB.COM/user/PROJECT",
    }
    assert extract_repo_url(urls) == "https://GITHUB.COM/user/PROJECT"


def test_stream_packages_from_jsonl(tmp_path: Path) -> None:
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


def test_stream_packages_datetime_parsing(tmp_path: Path) -> None:
    p = tmp_path / "pypi_date.jsonl"
    pkg = {
        "name": "date-pkg",
        "version": "1.0",
        "upload_time": "2023-01-01T12:00:00Z",  # Classic ISO
    }
    with open(p, "w") as f:
        f.write(json.dumps(pkg) + "\n")

    pkgs = list(stream_packages_from_jsonl(p))
    assert len(pkgs) == 1
    upload_time = pkgs[0].upload_time
    assert upload_time is not None
    assert upload_time.year == 2023
    assert upload_time.month == 1
    assert upload_time.day == 1

    # Test with +00:00 format
    pkg["upload_time"] = "2023-05-15T10:30:00+00:00"
    with open(p, "w") as f:
        f.write(json.dumps(pkg) + "\n")
    pkgs = list(stream_packages_from_jsonl(p))
    upload_time = pkgs[0].upload_time
    assert upload_time is not None
    assert upload_time.month == 5
    assert upload_time.day == 15

    # Test with invalid date
    pkg["upload_time"] = "invalid-date"
    with open(p, "w") as f:
        f.write(json.dumps(pkg) + "\n")
    pkgs = list(stream_packages_from_jsonl(p))
    # It should skip the package because PackageInfo validation will fail
    assert len(pkgs) == 0


@pytest.mark.asyncio
async def test_fetch_packages_from_api(monkeypatch: pytest.MonkeyPatch) -> None:
    class MockResponse:
        def __init__(self, data: dict[str, typing.Any], status: int = 200) -> None:
            self.data = data
            self.status = status

        async def __aenter__(self) -> "MockResponse":
            return self

        async def __aexit__(self, *args: typing.Any) -> None:
            pass

        async def json(self) -> dict[str, typing.Any]:
            return self.data

    class MockSession:
        def get(self, url: str) -> MockResponse:
            if "exists" in url:
                return MockResponse(
                    {"info": {"name": "exists", "version": "1.0"}, "urls": [{"upload_time": "2024-01-01T12:00:00"}]}
                )
            return MockResponse({}, status=404)

        async def __aenter__(self) -> "MockSession":
            return self

        async def __aexit__(self, *args: typing.Any) -> None:
            pass

    monkeypatch.setattr("aiohttp.ClientSession", lambda: MockSession())

    async def mock_sleep(x: float) -> None:
        pass

    monkeypatch.setattr("asyncio.sleep", mock_sleep)

    pkgs = []
    async for pkg in fetch_packages_from_api(["exists", "missing"]):
        pkgs.append(pkg)

    assert len(pkgs) == 1
    assert pkgs[0].name == "exists"
    upload_time = pkgs[0].upload_time
    assert upload_time is not None
    assert upload_time.year == 2024
