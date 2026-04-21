import logging
import yaml
from enum import Enum
from pathlib import Path
from typing import Any, List, Type, TypeVar

import instructor
from litellm import completion
from pydantic import BaseModel

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


class LLMTier(Enum):
    TIER_1 = "tier_1"
    TIER_2 = "tier_2"
    TIER_3 = "tier_3"


class LLMClient:
    def __init__(self, config_path: str = "llm_config.yaml") -> None:
        self.config = self._load_config(config_path)

        # We use instructor to patch litellm's completion
        # Note: litellm returns a response that instructor can parse if we use mode=instructor.Mode.TOOLS
        # but litellm itself has a completion() function that we want to use for provider abstraction.

        # instructor.from_litellm is the preferred way if available,
        # otherwise we can use from_openai with a custom client if needed.
        # However, liteLLM is compatible with the OpenAI SDK.

        self.client = instructor.from_litellm(completion)

    def _load_config(self, path: str) -> dict[str, Any]:
        if not Path(path).exists():
            logger.warning(f"Config {path} not found, using defaults")
            return {
                "default": {
                    "base_url": "http://127.0.0.1:1234/v1",
                    "model": "qwen3.5-2b-mlx",
                    "temperature": 0.0,
                }
            }
        with open(path, "r") as f:
            config: dict[str, Any] = yaml.safe_load(f)
            return config

    def completion(
        self,
        messages: List[dict[str, str]],
        response_model: Type[T],
        tier: LLMTier = LLMTier.TIER_3,
        **kwargs: Any,
    ) -> T:
        tier_config = self.config.get(tier.value, self.config.get("default", {}))

        model = tier_config.get("model")
        base_url = tier_config.get("base_url")
        api_key = tier_config.get("api_key", "sk-dummy")  # Use dummy key for local endpoints
        temperature = tier_config.get("temperature", 0.0)

        # Merge with kwargs
        call_kwargs = {
            "model": model,
            "messages": messages,
            "response_model": response_model,
            "temperature": temperature,
            "api_key": api_key,
            **kwargs,
        }

        if base_url:
            call_kwargs["api_base"] = base_url

        logger.debug(f"LLM Completion Call: model={model}, messages={len(messages)}")

        res: T = self.client.chat.completions.create(**call_kwargs)

        logger.debug(f"LLM Response received for {tier.value}")
        return res
