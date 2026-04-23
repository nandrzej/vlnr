import pytest
from unittest.mock import patch
from pathlib import Path
from vlnr.llm import LLMClient
from vlnr.models import TriageResult

@pytest.mark.asyncio
async def test_triage_llm_integration(tmp_path: Path) -> None:
    from vlnr.triage import triage_vulnerability
    client = LLMClient()
    
    mock_res = TriageResult(
        analysis="Definite SQL injection",
        plausibility=1.0,
        is_false_positive=False,
        suggested_cwe="CWE-89"
    )

    with patch("vlnr.llm.LLMClient.completion", return_value=mock_res):
        res = triage_vulnerability(
            hit_message="Possible SQL injection",
            source_code="user_input = request.args.get('id')",
            sink_code="db.execute(f'SELECT * FROM users WHERE id = {user_input}')",
            client=client,
        )

    assert res.plausibility > 0.5
    assert not res.is_false_positive
    assert "SQL" in res.analysis
