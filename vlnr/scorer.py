import math
from datetime import datetime, timezone
from typing import Literal, Iterable

from vlnr.llm import LLMClient, LLMTier
from vlnr.models import (
    CandidateRecord,
    IntentScore,
    PackageInfo,
    VulnerabilityIndex,
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


def compute_audit_interest_score(vuln_count: int) -> float:
    """
    New audit interest formula (inverted, non-monotonic):
    - 0 CVEs -> neutral (0.5)
    - 1–10 CVEs -> peak (approaches 1.0 at ~5 CVEs)
    - 50+ CVEs -> declining (approaches 0.5)

    Implementation: score = 1.0 - 0.5 * abs(log2(count + 1) - log2(6)) / log2(6) clamped to [0, 1].
    Peaks at count=5 (log2(6) - log2(6) = 0).
    At count=0: 1.0 - 0.5 * abs(0 - 2.585) / 2.585 = 1.0 - 0.5 = 0.5.
    At count=35: 1.0 - 0.5 * abs(log2(36) - log2(6)) / log2(6) = 1.0 - 0.5 * (5.17 - 2.585) / 2.585 = 1.0 - 0.5 = 0.5.
    """
    # Peak at 5 CVEs (count+1=6)
    # 0 CVEs -> 0.5
    # 35 CVEs -> 0.5
    # 5 CVEs -> 1.0
    val = 1.0 - 0.5 * abs(math.log2(vuln_count + 1) - math.log2(6)) / math.log2(6)
    return max(0.0, min(1.0, val))


def build_reverse_dependency_graph(packages: Iterable[PackageInfo]) -> dict[str, int]:
    """Build reverse dep graph from requires_dist, O(n)"""
    graph: dict[str, int] = {}
    for pkg in packages:
        for dist in pkg.requires_dist:
            # Extract name before extras/version specs
            # e.g. "requests (>=2.20.0)" -> "requests"
            dep_name = (
                dist.split()[0]
                .split("[")[0]
                .split("(")[0]
                .split(">")[0]
                .split("<")[0]
                .split("=")[0]
                .strip(";")
                .strip()
                .lower()
            )
            graph[dep_name] = graph.get(dep_name, 0) + 1
    return graph


def score_candidate(
    pkg: PackageInfo,
    vuln_index: VulnerabilityIndex,
    mode: Literal["discovery", "triage"] = "discovery",
    downloads: int = 0,
    repo_stars: int | None = None,
    centrality: float = 0.0,
    epss_score: float | None = None,
    cvss_score: float | None = None,
    max_downloads: int = 10_000_000,
    max_stars: int = 100_000,
    llm_client: LLMClient | None = None,
) -> CandidateRecord:
    """Full scoring pipeline for single package."""
    vulns = vuln_index.by_package.get(pkg.name.lower(), [])
    vuln_ids = get_vulnerability_ids(vulns)

    # If scores not provided, take max from known vulns
    if epss_score is None and vulns:
        epss_scores = [v.epss_score for v in vulns if v.epss_score is not None]
        if epss_scores:
            epss_score = max(epss_scores)

    if cvss_score is None and vulns:
        cvss_scores = [v.cvss_score for v in vulns if v.cvss_score is not None]
        if cvss_scores:
            cvss_score = max(cvss_scores)

    latest_vulnerable = any(is_version_affected(pkg.version, v) for v in vulns)

    now = datetime.now(timezone.utc)
    age_years = 1.0
    recency_days = 365
    recency_bonus = 0.0
    if pkg.upload_time:
        if pkg.upload_time.tzinfo is None:
            upload_time = pkg.upload_time.replace(tzinfo=timezone.utc)
        else:
            upload_time = pkg.upload_time
        age_years = (now - upload_time).days / 365.25
        recency_days = (now - upload_time).days
        if recency_days <= 30:
            recency_bonus = 0.5  # Increased bonus to reach ~15% impact in weighted sum

    # Popularity component
    norm_downloads = normalize_log(float(downloads) if downloads > 0 else 100.0, float(max_downloads))

    if repo_stars is None:
        # Reweight downloads to fill gap if stars unknown
        popularity_discovery = norm_downloads * 0.5
        popularity_triage = norm_downloads
    else:
        norm_stars = normalize_log(float(repo_stars), float(max_stars))
        popularity_discovery = (norm_downloads * 0.35) + (norm_stars * 0.15)
        popularity_triage = (norm_downloads * 0.35 + norm_stars * 0.15) / 0.5

    if mode == "discovery":
        # Score = centrality * 0.35 + popularity * 0.35 + recency * 0.15 + (unused buffer 0.15)
        # Weights normalized to sum to 1.0 (approx)
        # Weighting: centrality (0.35), downloads (0.35), stars (0.15), recency (0.15)
        candidate_score = (centrality * 0.35) + popularity_discovery + (recency_bonus * 0.3)
    else:  # triage
        # Score = 0.5 * EPSS + 0.2 * clamp(CVSS, 0, 10)/10 + 0.3 * popularity
        epss = epss_score if epss_score is not None else 0.0
        cvss = (min(10.0, max(0.0, cvss_score)) / 10.0) if cvss_score is not None else 0.0
        candidate_score = (0.5 * epss) + (0.2 * cvss) + (0.3 * popularity_triage)

    # LLM Intent Score (only for discovery or if requested)
    intent_val = None
    intent_reasoning = None
    if llm_client:
        try:
            res = get_intent_score(pkg, llm_client)
            intent_val = res.score
            intent_reasoning = res.reasoning
            # Adjust candidate_score by intent if present (50% boost/reduction potential)
            candidate_score = (candidate_score * 0.5) + (intent_val * 0.5)
        except Exception:
            pass

    audit_interest = compute_audit_interest_score(len(vulns))

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
        pop_repo_stars=float(repo_stars) if repo_stars is not None else None,
        age_years=age_years,
        update_recency_days=recency_days,
        known_vuln_count=len(vulns),
        latest_version_vulnerable=latest_vulnerable,
        intent_score=intent_val,
        intent_reasoning=intent_reasoning,
        candidate_score=candidate_score,
        audit_interest_score=audit_interest,
        **vuln_ids,
    )
