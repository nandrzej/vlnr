import pytest
from unittest.mock import patch
from vlnr.llm import LLMClient
from vlnr.triage import triage_vulnerabilities_batch, filter_plausible_findings
from vlnr.models import BatchTriageResult, IndividualTriageResult


@pytest.fixture
def llm_client():
    return LLMClient(config_path="llm_config.yaml")


def test_triage_batch_logic(llm_client):
    items = [
        {"slice_id": "1", "hit_message": "test", "source_code": "src", "sink_code": "sink"},
        {"slice_id": "2", "hit_message": "test2", "source_code": "src2", "sink_code": "sink2"},
    ]

    mock_batch_result = BatchTriageResult(
        results=[
            IndividualTriageResult(
                slice_id="1", analysis="Plausible", plausibility=0.8, is_false_positive=False, suggested_cwe="CWE-78"
            ),
            IndividualTriageResult(
                slice_id="2", analysis="False positive", plausibility=0.2, is_false_positive=True, suggested_cwe=None
            ),
        ]
    )

    with patch("vlnr.llm.LLMClient.completion") as mock_completion:
        mock_completion.return_value = mock_batch_result

        result = triage_vulnerabilities_batch(items, llm_client)

        assert len(result.results) == 2
        assert result.results[0].slice_id == "1"
        assert result.results[0].plausibility == 0.8

        # Test threshold filtering
        plausible = filter_plausible_findings(result, threshold=0.6)
        assert len(plausible) == 1
        assert plausible[0].slice_id == "1"


def test_triage_batch_max_size(llm_client):
    # Create 7 items
    items = [{"slice_id": str(i), "hit_message": "test", "source_code": "src", "sink_code": "sink"} for i in range(7)]

    with patch("vlnr.llm.LLMClient.completion") as mock_completion:
        # We don't care about the return value for this test, just the call
        mock_completion.return_value = BatchTriageResult(results=[])

        triage_vulnerabilities_batch(items, llm_client)

        # Verify only first 5 items were included in the prompt
        args, kwargs = mock_completion.call_args
        messages = kwargs["messages"]
        content = messages[0]["content"]
        assert "Analyze each of the following 5 tainted paths" in content
        assert "SLICE 5" not in content
