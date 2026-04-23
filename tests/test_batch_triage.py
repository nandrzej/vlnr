import pytest
from unittest.mock import patch
from vlnr.llm import LLMClient
from vlnr.models import BatchTriageResult, IndividualTriageResult
from vlnr.triage import triage_vulnerabilities_batch

@pytest.mark.asyncio
async def test_triage_vulnerabilities_batch() -> None:
    client = LLMClient()
    
    slices = [
        {
            "slice_id": "slice-1",
            "hit_message": "Possible SQL injection",
            "source_code": "user_id = request.args.get('id')",
            "sink_code": "cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
        },
        {
            "slice_id": "slice-2",
            "hit_message": "Hardcoded password",
            "source_code": "PASS = '12345'",
            "sink_code": "connect(password=PASS)",
        },
    ]

    mock_res = BatchTriageResult(
        results=[
            IndividualTriageResult(slice_id="slice-1", analysis="Analysis 1", plausibility=0.9, is_false_positive=False, suggested_cwe="CWE-89"),
            IndividualTriageResult(slice_id="slice-2", analysis="Analysis 2", plausibility=1.0, is_false_positive=False, suggested_cwe="CWE-259"),
        ]
    )

    with patch("vlnr.llm.LLMClient.completion", return_value=mock_res):
        batch_result = triage_vulnerabilities_batch(slices, client)

    assert len(batch_result.results) == 2
