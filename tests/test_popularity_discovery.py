import json
from pathlib import Path
from unittest.mock import AsyncMock, patch
import pytest
from vlnr.cli import run_pipeline


@pytest.fixture
def mock_pypi_jsonl(tmp_path: Path) -> Path:
    path = tmp_path / "mock_pypi.jsonl"
    packages = [
        # 10 low-download packages
        {
            "name": f"low-{i}",
            "version": "1.0.0",
            "summary": "Low download cli package",
            "classifiers": ["Framework :: Pytest"],
            "project_urls": {"Homepage": "https://github.com/org/low"},
            "upload_time": "2023-01-01T00:00:00Z",
        }
        for i in range(10)
    ]
    # 1 high-download package at the end
    packages.append(
        {
            "name": "high-pop",
            "version": "2.0.0",
            "summary": "High popularity ml package",
            "classifiers": ["Framework :: Pytest"],
            "project_urls": {"Homepage": "https://github.com/org/high"},
            "upload_time": "2023-01-01T00:00:00Z",
        }
    )

    with open(path, "w") as f:
        for p in packages:
            f.write(json.dumps(p) + "\n")
    return path


@pytest.fixture
def mock_downloads_csv(tmp_path: Path) -> Path:
    path = tmp_path / "downloads.csv"
    with open(path, "w") as f:
        for i in range(10):
            f.write(f"low-{i},10\n")
        f.write("high-pop,1000000\n")
    return path


@pytest.mark.asyncio
async def test_high_pop_package_discovery_at_end(
    mock_pypi_jsonl: Path, mock_downloads_csv: Path, tmp_path: Path
) -> None:
    out_path = tmp_path / "top.json"

    # Mock get_repo_stars to avoid network calls and verify it's called
    with patch("vlnr.cli.get_repo_stars", new_callable=AsyncMock) as mock_stars:
        mock_stars.return_value = 500

        await run_pipeline(
            pypi_json=mock_pypi_jsonl,
            downloads_csv=mock_downloads_csv,
            out=out_path,
            limit=2,
            osv_dump=Path("tests/fixtures/sample_osv.zip"),  # Use existing fixture
        )

    assert out_path.exists()
    with open(out_path, "r") as f:
        data = json.load(f)

    assert len(data) == 2
    # high-pop should be first because of its massive downloads
    assert data[0]["name"] == "high-pop"

    # Verify stars were fetched for high-pop (part of refinement)
    # The refinement buffer is max(limit * 3, 500), which is 500 here.
    # So all 11 packages should be refined.
    assert mock_stars.call_count == 11
