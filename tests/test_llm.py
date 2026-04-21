import pytest
from unittest.mock import patch, MagicMock
from vlnr.llm import LLMClient, LLMTier
from pydantic import BaseModel, Field


class SimpleResponse(BaseModel):
    answer: str = Field(description="The answer to the question")


@pytest.fixture
def llm_client():
    return LLMClient(config_path="llm_config.yaml")


def test_simple_completion(llm_client):
    messages = [{"role": "user", "content": "What is 2+2?"}]

    # Mock the return value of instructor's completion
    mock_response = SimpleResponse(answer="The answer is 4")

    with patch("vlnr.llm.instructor.from_litellm") as mock_instructor:
        mock_client = MagicMock()
        mock_instructor.return_value = mock_client
        mock_client.chat.completions.create.return_value = mock_response

        # Re-initialize client to use mocked instructor
        client = LLMClient(config_path="llm_config.yaml")

        response = client.completion(messages=messages, response_model=SimpleResponse, tier=LLMTier.TIER_3)

        assert isinstance(response, SimpleResponse)
        assert "4" in response.answer
        mock_client.chat.completions.create.assert_called_once()


def test_tier_routing(llm_client):
    messages = [{"role": "user", "content": "Ping"}]
    mock_response = SimpleResponse(answer="Pong")

    with patch("vlnr.llm.instructor.from_litellm") as mock_instructor:
        mock_client = MagicMock()
        mock_instructor.return_value = mock_client
        mock_client.chat.completions.create.return_value = mock_response

        client = LLMClient(config_path="llm_config.yaml")

        response = client.completion(messages=messages, response_model=SimpleResponse, tier=LLMTier.TIER_1)

        assert isinstance(response, SimpleResponse)
        # Verify it called with tier_1 config (temperature 0.1)
        args, kwargs = mock_client.chat.completions.create.call_args
        assert kwargs["temperature"] == 0.1
        assert kwargs["model"] == "custom_openai/qwen3.5-2b-mlx"
