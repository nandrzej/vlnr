import math
from datetime import datetime, timezone

from vlnr.llm import LLMClient, LLMTier
from vlnr.models import (
    CandidateRecord,
    IntentScore,
    PackageInfo,
    VulnerabilityIndex,
    DEFAULT_WEIGHTS,
    VULN_THRESHOLD_K,
    LOW_VULN_PENALTY,
)
from vlnr.osv import get_vulnerability_ids, is_version_affected


def get_intent_score(pkg: PackageInfo, client: LLMClient) -> IntentScore:
    """Get semantic intent score from LLM."""
    prompt = (
        f"Analyze the following Python package name and summary. "
        f"Determine if it belongs to a high-value security category "
        f"(authentication, cryptography, networking, data parsing, serialization, "
        f"web frameworks, database drivers, etc.). "
        f"Provide a score where 1.0 is extremely critical infrastructure and 0.0 is a trivial tool.\n\n"
        f"Package Name: {pkg.name}\n"
        f"Summary: {pkg.summary}"
    )

    return client.completion(
        messages=[{"role": "user", "content": prompt}],
        response_model=IntentScore,
        tier=LLMTier.TIER_3,
    )


def normalize_log(value: float, max_value: float) -> float:
    """Log-scale normalize to [0, 1]."""
    if value <= 0:
        return 0.0
    if max_value <= 1:
        return 1.0
    return min(1.0, math.log(value + 1) / math.log(max_value + 1))


def compute_audit_score(vuln_count: int) -> float:
    """
    Audit quality based on known vulnerability count.
    Uses log-decay so the score asymptotically approaches 0 but never reaches it,
    ensuring high-vuln packages remain visible for triage.

    - 0 vulns: 1.0 (no penalty)
    - 1-2 vulns: 0.8 (small penalty)
    - 3+ vulns: 1.0 / log2(count + 1) (log decay, e.g. 28 vulns -> 0.20)
    """
    if vuln_count == 0:
        return 1.0
    if vuln_count <= VULN_THRESHOLD_K:
        return 1.0 - LOW_VULN_PENALTY

    return 1.0 / math.log2(vuln_count + 1)


def score_candidate(
    pkg: PackageInfo,
    vuln_index: VulnerabilityIndex,
    downloads: int = 0,
    repo_stars: int = 0,
    max_downloads: int = 10_000_000,
    max_stars: int = 100_000,
    dependency_map: dict[str, int] | None = None,
    max_dependents: int = 10_000,
    llm_client: LLMClient | None = None,
) -> CandidateRecord:
    """Full scoring pipeline for single package."""
    vulns = vuln_index.by_package.get(pkg.name.lower(), [])
    vuln_ids = get_vulnerability_ids(vulns)

    latest_vulnerable = any(is_version_affected(pkg.version, v) for v in vulns)

    now = datetime.now(timezone.utc)
    age_years = 1.0  # Default to 1 year for missing date
    recency_days = 365
    if pkg.upload_time:
        # Handle naive datetimes from fromisoformat if they don't have timezone
        if pkg.upload_time.tzinfo is None:
            upload_time = pkg.upload_time.replace(tzinfo=timezone.utc)
        else:
            upload_time = pkg.upload_time
        age_years = (now - upload_time).days / 365.25
        recency_days = (now - upload_time).days

    # Popularity component
    # Use a small baseline for downloads if missing from map (small footprint)
    adj_downloads = float(downloads) if downloads > 0 else 100.0
    norm_downloads = normalize_log(adj_downloads, float(max_downloads))
    norm_stars = normalize_log(float(repo_stars), float(max_stars))
    if dependency_map is not None:
        deps = dependency_map.get(pkg.name.lower(), 0)
        centrality = normalize_log(float(deps), float(max_dependents))
    else:
        # Centrality is fixed at 0.5 for now per spec
        centrality = 0.5

    pop_score = (
        norm_downloads * DEFAULT_WEIGHTS["downloads"]
        + centrality * DEFAULT_WEIGHTS["centrality"]
        + norm_stars * DEFAULT_WEIGHTS["stars"]
    )

    # Audit component
    audit_score = compute_audit_score(len(vulns))

    # LLM Intent Score
    intent_val = None
    intent_reasoning = None
    if llm_client:
        try:
            res = get_intent_score(pkg, llm_client)
            intent_val = res.score
            intent_reasoning = res.reasoning
            # Adjust pop_score by intent if present (50% boost/reduction potential)
            pop_score = (pop_score * 0.5) + (intent_val * 0.5)
        except Exception:
            # Fallback to pure popularity on LLM failure
            pass

    # Final candidate score
    candidate_score = pop_score * audit_score

    return CandidateRecord(
        name=pkg.name,
        version=pkg.version,
        summary=pkg.summary,
        classifiers=pkg.classifiers,
        category_tags=pkg.category_tags,
        pypi_url=f"https://pypi.org/project/{pkg.name}/",
        repo_url=pkg.repo_url,
        pop_downloads=float(downloads),
        centrality_dep=centrality,
        pop_repo_stars=float(repo_stars),
        age_years=age_years,
        update_recency_days=recency_days,
        known_vuln_count=len(vulns),
        latest_version_vulnerable=latest_vulnerable,
        intent_score=intent_val,
        intent_reasoning=intent_reasoning,
        candidate_score=candidate_score,
        audit_interest_score=0.0,  # TODO: Implement actual audit interest logic
        **vuln_ids,
    )
