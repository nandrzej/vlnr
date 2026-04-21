import logging
from pydantic import BaseModel, Field
from vlnr.llm import LLMClient, LLMTier

logger = logging.getLogger(__name__)


class PoCResult(BaseModel):
    exploit_code: str = Field(description="Self-contained Python script to demonstrate the vulnerability")
    prerequisites: list[str] = Field(description="Dependencies or environment setup required")
    verification_steps: str
    suggested_cwe: str | None = Field(description="The CWE ID most applicable to this vulnerability")


def generate_poc(
    package_name: str, vulnerability_context: str, client: LLMClient, suggested_cwe: str | None = None
) -> PoCResult:
    """Generate a PoC exploit script for a high-confidence finding using Tier 1 model."""

    cwe_hint = f" (Focus on {suggested_cwe})" if suggested_cwe else ""

    prompt = (
        f"You are a security researcher developing a Proof of Concept (PoC) for a verified vulnerability. "
        f"Target Package: {package_name}\n"
        f"Vulnerability Context: {vulnerability_context}\n"
        f"CWE Hint: {suggested_cwe if suggested_cwe else 'Unknown'}\n\n"
        f"Generate a self-contained Python script that demonstrates the vulnerability{cwe_hint}. "
        f"Explicitly list all prerequisites (e.g., in a requirements.txt style list if necessary) and provide clear verification steps.\n\n"
        f"Confirm the suggested CWE in your final response.\n\n"
        f"# FOR EDUCATIONAL/SECURITY RESEARCH ONLY. DO NOT RUN ON UNTRUSTED SYSTEMS."
    )

    return client.completion(
        messages=[{"role": "user", "content": prompt}],
        response_model=PoCResult,
        tier=LLMTier.TIER_1,
    )
