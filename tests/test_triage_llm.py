import pytest
import vcr
from pathlib import Path
from vlnr.llm import LLMClient


@pytest.mark.asyncio
async def test_triage_llm_integration(my_vcr: vcr.VCR, tmp_path: Path) -> None:
    # We need a real-ish slice or at least the structure
    # Since process_package handles source fetching, we might need a more isolated test for triage logic
    # or just use a small real package if available.
    # Let's test the triage_vulnerability function directly first.
    from vlnr.triage import triage_vulnerability

    client = LLMClient()

    with my_vcr.use_cassette("test_triage_llm_integration.yaml"):
        res = triage_vulnerability(
            hit_message="Possible SQL injection",
            source_code="user_input = request.args.get('id')",
            sink_code="db.execute(f'SELECT * FROM users WHERE id = {user_input}')",
            client=client,
        )

        assert res.plausibility > 0.5
        assert not res.is_false_positive
        assert "SQL" in res.analysis
