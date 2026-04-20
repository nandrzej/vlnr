import pytest
import vcr
from vlnr.llm import LLMClient, LLMTier
from pydantic import BaseModel


class SimpleModel(BaseModel):
    answer: str


@pytest.mark.asyncio
async def test_llm_client_completion(my_vcr: vcr.VCR) -> None:
    client = LLMClient()

    with my_vcr.use_cassette("test_llm_completion.yaml"):
        resp = client.completion(
            messages=[{"role": "user", "content": "Say 'hello' in a JSON object with key 'answer'"}],
            response_model=SimpleModel,
            tier=LLMTier.TIER_3,
        )
        assert "hello" in resp.answer.lower()
