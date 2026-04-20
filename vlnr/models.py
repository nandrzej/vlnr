from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


VexStatus = Literal[
    "not_affected",
    "affected",
    "fixed",
    "under_investigation",
]


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
    cvss_score: float | None = None
    epss_score: float | None = None
    vex_status: VexStatus = "under_investigation"


class VulnerabilityIndex(BaseModel):
    """Lookup index: package_name -> vulnerability records."""

    by_package: dict[str, list[VulnerabilityRecord]] = Field(default_factory=dict)


class IntentScore(BaseModel):
    reasoning: str = Field(description="Brief explanation of the intent")
    score: float = Field(ge=0, le=1, description="Intent score from 0 to 1")
    is_high_value: bool = Field(description="Whether the project is a high-value security target")


class TriageResult(BaseModel):
    analysis: str = Field(description="Step-by-step analysis of the tainted path")
    plausibility: float = Field(ge=0, le=1, description="Likelihood of this being a real vulnerability")
    is_false_positive: bool
    suggested_cwe: str | None


class IndividualTriageResult(TriageResult):
    slice_id: str


class BatchTriageResult(BaseModel):
    results: list[IndividualTriageResult]


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
    intent_score: float | None = None
    intent_reasoning: str | None = None
    candidate_score: float = 0.0
    audit_interest_score: float = 0.0


# Hardcoded defaults - no config file needed
DEFAULT_WEIGHTS = {"downloads": 0.4, "centrality": 0.4, "stars": 0.2}
VULN_THRESHOLD_K = 2
LOW_VULN_PENALTY = 0.2
