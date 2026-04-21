import logging
from typing import List, Dict

from vlnr.llm import LLMClient, LLMTier
from vlnr.models import TriageResult, BatchTriageResult, IndividualTriageResult

logger = logging.getLogger(__name__)


def triage_vulnerability(
    hit_message: str,
    source_code: str,
    sink_code: str,
    client: LLMClient,
    file_line: str = "",
    context: str = "",
) -> TriageResult:
    """Triage a discovered tainted path using SLM."""
    prompt = (
        f"You are a security expert triaging static analysis results. "
        f"Analyze the following tainted path and determine if it is a plausible vulnerability "
        f"or a false positive.\n\n"
        f"Location: {file_line}\n"
        f"Tool Hit: {hit_message}\n"
        f"Source Code: {source_code}\n"
        f"Sink Code: {sink_code}\n"
        f"Additional Context: {context}\n\n"
        f"Analyze the flow, sanitization, and reachability. "
        f"Provide a step-by-step reasoning, a plausibility score (0-1), and a suggested CWE if applicable."
    )

    return client.completion(
        messages=[{"role": "user", "content": prompt}],
        response_model=TriageResult,
        tier=LLMTier.TIER_2,
    )


def triage_vulnerabilities_batch(
    items: List[Dict[str, str]],
    client: LLMClient,
) -> BatchTriageResult:
    """Triage multiple vulnerabilities in a single LLM call. Max batch size 5."""
    if len(items) > 5:
        logger.warning(f"Batch size {len(items)} exceeds recommended max of 5. Capping.")
        items = items[:5]

    batch_str = ""
    for item in items:
        batch_str += (
            f"--- SLICE {item['slice_id']} ---\n"
            f"Location: {item.get('file_line', 'unknown')}\n"
            f"Hit: {item['hit_message']}\n"
            f"Source:\n{item['source_code']}\n"
            f"Sink:\n{item['sink_code']}\n\n"
        )

    prompt = (
        f"You are a security expert triaging multiple static analysis results. "
        f"Analyze each of the following {len(items)} tainted paths and determine if they are "
        f"plausible vulnerabilities or false positives.\n\n"
        f"{batch_str}"
        f"For each SLICE, provide a step-by-step reasoning, a plausibility score (0-1), "
        "indicate if it is a false positive, and suggest a CWE if applicable. "
        "Map each result back to its slice_id."
    )

    return client.completion(
        messages=[{"role": "user", "content": prompt}],
        response_model=BatchTriageResult,
        tier=LLMTier.TIER_2,
    )


def filter_plausible_findings(batch_result: BatchTriageResult, threshold: float = 0.6) -> List[IndividualTriageResult]:
    """Filter findings based on a plausibility threshold."""
    return [res for res in batch_result.results if res.plausibility >= threshold]
