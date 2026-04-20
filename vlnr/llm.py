import os
import logging
from enum import Enum
from typing import Any, Type, TypeVar, List

import instructor
from openai import OpenAI
from openai.types.chat import (
    ChatCompletionAssistantMessageParam,
    ChatCompletionDeveloperMessageParam,
    ChatCompletionFunctionMessageParam,
    ChatCompletionSystemMessageParam,
    ChatCompletionToolMessageParam,
    ChatCompletionUserMessageParam,
)
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

ChatCompletionMessageParam = (
    ChatCompletionDeveloperMessageParam
    | ChatCompletionSystemMessageParam
    | ChatCompletionUserMessageParam
    | ChatCompletionAssistantMessageParam
    | ChatCompletionToolMessageParam
    | ChatCompletionFunctionMessageParam
)


class LLMTier(Enum):
    # Updated to Google Gemma 4 31B defaults as requested
    TIER_1 = os.environ.get("LLM_MODEL_TIER_1", "google/gemma-4-31b-it")  # Deep Reasoning
    TIER_2 = os.environ.get("LLM_MODEL_TIER_2", "google/gemma-4-31b-it")  # Triage / Refinement
    TIER_3 = os.environ.get("LLM_MODEL_TIER_3", "meta/llama-3.1-8b-instruct")  # Metadata / Rapid Scoring


class LLMClient:
    def __init__(self) -> None:
        self.base_url = os.environ.get("LLM_BASE_URL", "https://integrate.api.nvidia.com/v1")
        self.api_key = os.environ.get("LLM_API_KEY")

        if not self.api_key:
            raise ValueError("LLM_API_KEY environment variable is not set")

        # Gemma 4 31B supports native function calling, using Mode.TOOLS as per decision
        self.client = instructor.from_openai(
            OpenAI(
                base_url=self.base_url,
                api_key=self.api_key,
            ),
            mode=instructor.Mode.TOOLS,
        )

    def completion(
        self,
        messages: List[ChatCompletionMessageParam],
        response_model: Type[T],
        tier: LLMTier = LLMTier.TIER_3,
        **kwargs: Any,
    ) -> T:
        logger.debug(f"LLM Completion Call: model={tier.value}, messages={len(messages)}")
        res: T = self.client.chat.completions.create(
            model=tier.value, messages=messages, response_model=response_model, **kwargs
        )
        logger.debug(f"LLM Response received from {tier.value}")
        return res
