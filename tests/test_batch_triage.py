import pytest
from vlnr.llm import LLMClient
from vlnr.triage import triage_vulnerabilities_batch
from vlnr.models import BatchTriageResult

@pytest.mark.asyncio
async def test_triage_vulnerabilities_batch(my_vcr):
    client = LLMClient()
    items = [
        {
            "slice_id": "slice-1",
            "hit_message": "Possible SQL injection",
            "source_code": "user_id = request.args.get('id')",
            "sink_code": "cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
            "file_line": "app.py:10"
        },
        {
            "slice_id": "slice-2",
            "hit_message": "Hardcoded password",
            "source_code": "PASS = '12345'",
            "sink_code": "connect(password=PASS)",
            "file_line": "config.py:5"
        }
    ]

    with my_vcr.use_cassette("test_triage_batch.yaml"):
        res = triage_vulnerabilities_batch(items, client)
        
    assert isinstance(res, BatchTriageResult)
    assert len(res.results) == 2
    
    ids = [r.slice_id for r in res.results]
    assert "slice-1" in ids
    assert "slice-2" in ids
    
    # Check specific results
    r1 = next(r for r in res.results if r.slice_id == "slice-1")
    assert r1.plausibility > 0.5
    assert not r1.is_false_positive
    
    r2 = next(r for r in res.results if r.slice_id == "slice-2")
    assert r2.plausibility > 0.5
    assert not r2.is_false_positive
