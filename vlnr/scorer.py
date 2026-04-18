import math
from datetime import datetime, timezone

from vlnr.models import (
    CandidateRecord,
    PackageInfo,
    VulnerabilityIndex,
    DEFAULT_WEIGHTS,
    VULN_THRESHOLD_K,
    LOW_VULN_PENALTY,
    HIGH_VULN_BASE_PENALTY,
)
from vlnr.osv import get_vulnerability_ids, is_version_affected


def normalize_log(value: float, max_value: float) -> float:
    """Log-scale normalize to [0, 1]."""
    if value <= 0:
        return 0.0
    if max_value <= 1:
        return 1.0
    return min(1.0, math.log(value + 1) / math.log(max_value + 1))


def compute_audit_score(vuln_count: int) -> float:
    """
    - 0 vulns: 1.0 (no penalty)
    - 1-2 vulns: 0.8 (small penalty)
    - 3+ vulns: 0.5 - (count - 2) * 0.1 (larger penalty)
    """
    if vuln_count == 0:
        return 1.0
    if vuln_count <= VULN_THRESHOLD_K:
        return 1.0 - LOW_VULN_PENALTY

    penalty = HIGH_VULN_BASE_PENALTY + (vuln_count - VULN_THRESHOLD_K) * 0.1
    return max(0.0, 1.0 - penalty)


def score_candidate(
    pkg: PackageInfo,
    vuln_index: VulnerabilityIndex,
    downloads: int = 0,
    repo_stars: int = 0,
    max_downloads: int = 10_000_000,
    max_stars: int = 100_000,
    dependency_map: dict[str, int] | None = None,
    max_dependents: int = 10_000,
) -> CandidateRecord:
    """Full scoring pipeline for single package."""
    vulns = vuln_index.by_package.get(pkg.name.lower(), [])
    vuln_ids = get_vulnerability_ids(vulns)

    latest_vulnerable = any(is_version_affected(pkg.version, v) for v in vulns)

    now = datetime.now(timezone.utc)
    age_years = 0.0
    recency_days = 0
    if pkg.upload_time:
        age_years = (now - pkg.upload_time).days / 365.25
        recency_days = (now - pkg.upload_time).days

    # Popularity component
    norm_downloads = normalize_log(float(downloads), float(max_downloads))
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
        candidate_score=candidate_score,
        **vuln_ids,
    )
