import json
from pathlib import Path
from vlnr.cli import run_pipeline
import pytest

@pytest.mark.asyncio
async def test_full_pipeline_with_fixtures(tmp_path):
    pypi_json = Path("tests/fixtures/sample_pypi.jsonl")
    osv_dump = Path("tests/fixtures/sample_osv.zip")
    out_path = tmp_path / "top_candidates.json"
    
    await run_pipeline(
        pypi_json=pypi_json,
        osv_dump=osv_dump,
        out=out_path,
        limit=10,
        include_cli=True,
        include_ml=True,
        include_dev=True
    )
    
    assert out_path.exists()
    with open(out_path, "r") as f:
        data = json.load(f)
        
    assert len(data) == 3
    # Check that vuln-package has vulnerability info
    vuln_pkg = next(p for p in data if p["name"] == "vuln-package")
    assert vuln_pkg["known_vuln_count"] == 1
    assert vuln_pkg["latest_version_vulnerable"] is True
    assert "V-1" in vuln_pkg["osv_ids"]
    
    # Check category tags
    cli_tool = next(p for p in data if p["name"] == "test-cli-tool")
    assert "cli" in cli_tool["category_tags"]
    
    ml_lib = next(p for p in data if p["name"] == "test-ml-lib")
    assert "ml" in ml_lib["category_tags"]
