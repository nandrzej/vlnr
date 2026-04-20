import pytest
import json
import vcr
from pathlib import Path
from vlnr.cli import run_pipeline


@pytest.mark.asyncio
async def test_discovery_llm_integration(my_vcr: vcr.VCR, tmp_path: Path) -> None:
    # Dummy osv dump if needed, but we can skip it by not providing one
    out_file = tmp_path / "top_candidates_llm.json"

    # Mocking environment for VCR if needed, or just let it record
    with my_vcr.use_cassette("test_discovery_llm_integration.yaml"):
        await run_pipeline(packages="cryptography,flask", limit=2, llm_discovery=True, out=out_file)

    assert out_file.exists()
    with open(out_file, "r") as f:
        data = json.load(f)
        assert len(data) > 0
        # Check if intent_score is present
        assert "intent_score" in data[0]
        assert data[0]["intent_score"] is not None
