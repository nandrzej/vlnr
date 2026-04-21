from datetime import datetime, timedelta
from vlnr.models import PackageInfo, VulnerabilityIndex
from vlnr.scorer import (
    compute_audit_interest_score,
    normalize_log,
    score_candidate,
    build_reverse_dependency_graph,
)


def test_normalize_log() -> None:
    assert normalize_log(0, 100) == 0.0
    assert normalize_log(100, 100) == 1.0
    val = normalize_log(10, 100)
    assert 0.5 < val < 0.6


def test_audit_interest_inverted() -> None:
    """5 CVEs > 0 CVEs > 60 CVEs (non-monotonic, bounded)"""
    score_0 = compute_audit_interest_score(0)
    score_5 = compute_audit_interest_score(5)
    score_60 = compute_audit_interest_score(60)

    assert score_5 > score_0
    assert score_0 > score_60
    assert 0 <= score_0 <= 1
    assert 0 <= score_5 <= 1
    assert 0 <= score_60 <= 1


def test_discovery_score_centrality_weight() -> None:
    """certifi/urllib3 rank high due to centrality weight"""
    pkg1 = PackageInfo(name="certifi", version="1.0")
    pkg2 = PackageInfo(name="low-centrality", version="1.0")
    vuln_index = VulnerabilityIndex()

    # pkg1: high centrality, pkg2: low centrality. Same downloads.
    cand1 = score_candidate(pkg1, vuln_index, downloads=1000, centrality=0.9, mode="discovery")
    cand2 = score_candidate(pkg2, vuln_index, downloads=1000, centrality=0.1, mode="discovery")

    assert cand1.candidate_score > cand2.candidate_score


def test_discovery_score_recency_bonus() -> None:
    """10-15% bonus for 30-day upload recency"""
    recent_time = datetime.now() - timedelta(days=10)
    old_time = datetime.now() - timedelta(days=100)

    pkg_recent = PackageInfo(name="recent", version="1.0", upload_time=recent_time)
    pkg_old = PackageInfo(name="old", version="1.0", upload_time=old_time)
    vuln_index = VulnerabilityIndex()

    cand_recent = score_candidate(pkg_recent, vuln_index, downloads=1000, mode="discovery")
    cand_old = score_candidate(pkg_old, vuln_index, downloads=1000, mode="discovery")

    # Recency bonus is 0.125 * 0.2 (weight) = 0.025 absolute diff if other components 0
    # But it's 12.5% bonus to pop_score? Plan says: "recency = 0.125 ... if upload_time within 30 days"
    # "Score = centrality * w1 + popularity * w2 + recency * w3" where w3=0.2.
    # So it adds 0.125 * 0.2 = 0.025 to the total score.
    assert cand_recent.candidate_score > cand_old.candidate_score


def test_discovery_score_unknown_stars_excluded() -> None:
    """repo_stars=None (unknown host) does not penalize vs stars=0"""
    pkg = PackageInfo(name="test", version="1.0")
    vuln_index = VulnerabilityIndex()

    # stars=None should reweight downloads.
    # If downloads=0, both should be 0 (excluding centrality/recency).
    cand_none = score_candidate(pkg, vuln_index, downloads=1000, repo_stars=None, mode="discovery")
    cand_zero = score_candidate(pkg, vuln_index, downloads=1000, repo_stars=0, mode="discovery")

    # With stars=0, popularity = (norm_dl * 0.8 + norm_stars * 0.2) or similar.
    # With stars=None, popularity = norm_dl * 1.0.
    # norm_dl for 1000 is positive, norm_stars for 0 is 0.
    # So cand_none should be >= cand_zero.
    assert cand_none.candidate_score >= cand_zero.candidate_score


def test_triage_score_formula() -> None:
    """Score = 0.5*EPSS + 0.2*clamp(CVSS) + 0.3*Popularity"""
    pkg = PackageInfo(name="test", version="1.0")
    vuln_index = VulnerabilityIndex()

    # High EPSS/CVSS
    cand1 = score_candidate(pkg, vuln_index, epss_score=0.9, cvss_score=9.0, mode="triage")
    # Low EPSS/CVSS
    cand2 = score_candidate(pkg, vuln_index, epss_score=0.1, cvss_score=3.0, mode="triage")

    assert cand1.candidate_score > cand2.candidate_score


def test_triage_score_missing_epss_cvss() -> None:
    """EPSS=None/CVSS=None treated as 0 in triage"""
    pkg = PackageInfo(name="test", version="1.0")
    vuln_index = VulnerabilityIndex()

    cand_none = score_candidate(pkg, vuln_index, epss_score=None, cvss_score=None, mode="triage")
    cand_zero = score_candidate(pkg, vuln_index, epss_score=0.0, cvss_score=0.0, mode="triage")

    assert cand_none.candidate_score == cand_zero.candidate_score


def test_build_reverse_dependency_graph() -> None:
    """Build reverse dep graph from requires_dist, O(n)"""
    pkgs = [
        PackageInfo(name="A", version="1.0", requires_dist=["B", "C"]),
        PackageInfo(name="B", version="1.0", requires_dist=["C"]),
        PackageInfo(name="C", version="1.0"),
    ]
    graph = build_reverse_dependency_graph(pkgs)
    assert graph["c"] == 2  # A and B depend on C
    assert graph["b"] == 1  # A depends on B
    assert "a" not in graph or graph["a"] == 0


def test_centrality_captured() -> None:
    """Large dependent count leads to higher score"""
    pkg = PackageInfo(name="certifi", version="1.0")
    vuln_index = VulnerabilityIndex()

    # High dependent count -> higher centrality param
    cand1 = score_candidate(pkg, vuln_index, centrality=0.8, mode="discovery")
    cand2 = score_candidate(pkg, vuln_index, centrality=0.1, mode="discovery")

    assert cand1.candidate_score > cand2.candidate_score
