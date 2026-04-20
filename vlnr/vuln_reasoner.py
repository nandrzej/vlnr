from pydantic import BaseModel, Field
from vlnr.llm import LLMClient, LLMTier


class PoCResult(BaseModel):
    exploit_code: str = Field(description="Self-contained Python script to demonstrate the vulnerability")
    prerequisites: list[str] = Field(description="Dependencies or environment setup required")
    verification_steps: str


def generate_poc(package_name: str, vulnerability_context: str, client: LLMClient) -> PoCResult:
    """Generate a PoC exploit script for a high-confidence finding using Tier 1 model."""
    prompt = (
        f"You are a security researcher developing a Proof of Concept (PoC) for a verified vulnerability. "
        f"Target Package: {package_name}\
"
        f"Vulnerability Context: {vulnerability_context}\
\
"
        f"Generate a self-contained Python script that demonstrates the vulnerability. "
        f"Explicitly list all prerequisites (e.g., in a requirements.txt style list if necessary) and provide clear verification steps.\
\
"
        f"# FOR EDUCATIONAL/SECURITY RESEARCH ONLY. DO NOT RUN ON UNTRUSTED SYSTEMS."
    )

    return client.completion(
        messages=[{"role": "user", "content": prompt}],
        response_model=PoCResult,
        tier=LLMTier.TIER_1,
    )
