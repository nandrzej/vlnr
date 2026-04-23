import pytest
import json
from unittest.mock import patch
from pathlib import Path
from vlnr.cli import run_pipeline
from vlnr.models import IntentScore

@pytest.mark.asyncio
async def test_discovery_llm_integration(tmp_path: Path) -> None:
    out_file = tmp_path / "top_candidates_llm.json"
    
    mock_res = IntentScore(
        reasoning="High value",
        score=0.9,
        is_high_value=True
    )

    with patch("vlnr.llm.LLMClient.completion", return_value=mock_res):
        await run_pipeline(packages="cryptography,flask", limit=2, llm_discovery=True, out=out_file)

    assert out_file.exists()
    with open(out_file, "r") as f:
        data = json.load(f)
        assert len(data) > 0
        assert "intent_score" in data[0]
        assert data[0]["intent_score"] is not None
