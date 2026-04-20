from vlnr.models import PackageInfo, VulnerabilityIndex, VulnerabilityRecord
from vlnr.scorer import compute_audit_score, normalize_log, score_candidate


def test_normalize_log() -> None:
    assert normalize_log(0, 100) == 0.0
    assert normalize_log(100, 100) == 1.0
    # log(11) / log(101) approx 2.4/4.6 approx 0.52
    val = normalize_log(10, 100)
    assert 0.5 < val < 0.6


def test_compute_audit_score() -> None:
    assert compute_audit_score(0) == 1.0
    assert compute_audit_score(1) == 0.8
    assert compute_audit_score(2) == 0.8
    # 3 vulns: 1.0 / log2(3+1) = 1.0 / 2.0 = 0.5
    assert round(compute_audit_score(3), 1) == 0.5
    # High vuln count should never reach zero
    assert compute_audit_score(100) > 0.0


def test_score_candidate() -> None:
    pkg = PackageInfo(name="test", version="1.0", classifiers=["Environment :: Console"], category_tags=["cli"])
    vuln_index = VulnerabilityIndex()

    # Base case: 0 downloads, 0 stars, 0 vulns
    # Pop = normalize_log(100, 10^7)*0.4 + 0.5*0.4 + 0*0.2 approx 0.3145
    # Audit = 1.0
    # Final = 0.3145
    cand = score_candidate(pkg, vuln_index)
    assert round(cand.candidate_score, 4) == 0.3145

    # Case with downloads and stars
    # Max downloads: 10,000,000, max stars: 100,000
    # normalize_log(10_000_000, 10_000_000) = 1.0
    # normalize_log(100_000, 100_000) = 1.0
    # Pop = 1.0*0.4 + 0.5*0.4 + 1.0*0.2 = 0.4 + 0.2 + 0.2 = 0.8
    # Final = 0.8
    cand = score_candidate(pkg, vuln_index, downloads=10_000_000, repo_stars=100_000)
    assert round(cand.candidate_score, 1) == 0.8

    # Case with vulnerability
    # Pop = 0.3145, Audit = 0.8 (1 vuln) -> Final = 0.2516
    vuln_index.by_package["test"] = [VulnerabilityRecord(id="V-1", package_name="test")]
    cand = score_candidate(pkg, vuln_index)
    assert round(cand.candidate_score, 4) == 0.2516


def test_score_candidate_neutral_centrality() -> None:
    pkg = PackageInfo(name="test", version="1.0")
    vuln_index = VulnerabilityIndex()

    # When dependency_map is None, centrality should be 0.5
    cand = score_candidate(pkg, vuln_index, dependency_map=None)
    assert cand.centrality_dep == 0.5

    # When dependency_map is provided but empty, centrality should be 0.0 (log(0+1)/log(max+1))
    cand = score_candidate(pkg, vuln_index, dependency_map={})
    assert cand.centrality_dep == 0.0
