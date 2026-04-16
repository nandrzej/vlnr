from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class PackageInfo(BaseModel):
    """Minimal PyPI package representation."""

    name: str
    version: str
    summary: str = ""
    classifiers: list[str] = Field(default_factory=list)
    project_urls: dict[str, str] = Field(default_factory=dict)
    upload_time: datetime | None = None
    console_scripts: list[str] = Field(default_factory=list)

    # Derived after extraction
    repo_url: str | None = None
    category_tags: list[str] = Field(default_factory=list)


class VulnerabilityRecord(BaseModel):
    """Simplified OSV record for matching."""

    id: str
    aliases: list[str] = Field(default_factory=list)
    package_name: str
    affected_versions: list[str] = Field(default_factory=list)
    ranges: list[dict[str, Any]] = Field(default_factory=list)


class VulnerabilityIndex(BaseModel):
    """Lookup index: package_name -> vulnerability records."""

    by_package: dict[str, list[VulnerabilityRecord]] = Field(default_factory=dict)


class CandidateRecord(BaseModel):
    """Output schema - MUST match spec exactly."""

    name: str
    version: str
    summary: str
    classifiers: list[str]
    category_tags: list[str]
    pypi_url: str
    repo_url: str | None
    pop_downloads: float = 0.0
    centrality_dep: float = 0.5  # Fixed neutral value
    pop_repo_stars: float = 0.0
    age_years: float = 0.0
    update_recency_days: int = 0
    known_vuln_count: int = 0
    latest_version_vulnerable: bool = False
    osv_ids: list[str] = Field(default_factory=list)
    pysec_ids: list[str] = Field(default_factory=list)
    ghsa_ids: list[str] = Field(default_factory=list)
    candidate_score: float = 0.0


# Hardcoded defaults - no config file needed
DEFAULT_WEIGHTS = {"downloads": 0.4, "centrality": 0.4, "stars": 0.2}
VULN_THRESHOLD_K = 2
LOW_VULN_PENALTY = 0.2
HIGH_VULN_BASE_PENALTY = 0.5
