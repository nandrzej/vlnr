import pytest
import vcr
from vlnr.llm import LLMClient
from vlnr.models import IndividualTriageResult
from vlnr.triage import triage_vulnerabilities_batch


@pytest.mark.asyncio
async def test_triage_vulnerabilities_batch(my_vcr: vcr.VCR) -> None:
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

    with my_vcr.use_cassette("test_batch_triage.yaml"):
        batch_result = triage_vulnerabilities_batch(slices, client)

    assert len(batch_result.results) == 2
    assert isinstance(batch_result.results[0], IndividualTriageResult)
    assert batch_result.results[0].slice_id == "slice-1"
    assert batch_result.results[1].slice_id == "slice-2"
