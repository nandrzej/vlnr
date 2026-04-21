from pathlib import Path
import json
import zipfile
import pytest
from vlnr.osv import load_osv_index, is_version_affected, get_vulnerability_ids, load_epss_scores
from vlnr.models import VulnerabilityRecord
import gzip


def test_is_version_affected() -> None:
    vuln = VulnerabilityRecord(
        id="CVE-2024-1234",
        package_name="testpkg",
        affected_versions=["1.0.0"],
        ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "1.1.0"}, {"fixed": "1.2.0"}]}],
    )

    assert is_version_affected("1.0.0", vuln) is True
    assert is_version_affected("1.1.0", vuln) is True
    assert is_version_affected("1.1.5", vuln) is True
    assert is_version_affected("1.2.0", vuln) is False
    assert is_version_affected("0.9.0", vuln) is False


def test_load_osv_index(tmp_path: Path) -> None:
    zip_p = tmp_path / "osv.zip"
    vuln_data = {
        "id": "GHSA-xxxx-yyyy",
        "aliases": ["PYSEC-2024-1"],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "vulnpkg"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                "versions": ["1.0"],
            }
        ],
    }

    with zipfile.ZipFile(zip_p, "w") as z:
        z.writestr("vuln.json", json.dumps(vuln_data))

    index = load_osv_index(zip_p)
    assert "vulnpkg" in index.by_package
    assert len(index.by_package["vulnpkg"]) == 1
    assert index.by_package["vulnpkg"][0].id == "GHSA-xxxx-yyyy"


def test_get_vulnerability_ids() -> None:
    vulns = [
        VulnerabilityRecord(id="OSV-1", aliases=["PYSEC-1", "GHSA-1"], package_name="a"),
        VulnerabilityRecord(id="OSV-2", aliases=["GHSA-2"], package_name="a"),
    ]
    ids = get_vulnerability_ids(vulns)
    assert ids["osv_ids"] == ["OSV-1", "OSV-2"]
    assert ids["pysec_ids"] == ["PYSEC-1"]
    assert ids["ghsa_ids"] == ["GHSA-1", "GHSA-2"]


def test_is_version_affected_with_local_versions() -> None:
    # Vulnerability fixed in 1.2.3+local.1
    # Specifier should be <1.2.3
    vuln = VulnerabilityRecord(
        id="CVE-2024-5678",
        package_name="testpkg",
        affected_versions=[],
        ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.3+local.1"}]}],
    )

    # 1.2.2 is affected (1.0.0 <= 1.2.2 < 1.2.3)
    assert is_version_affected("1.2.2", vuln) is True
    # 1.2.3 is NOT affected (1.2.3 is not < 1.2.3)
    assert is_version_affected("1.2.3", vuln) is False
    # 1.0.0 is affected
    assert is_version_affected("1.0.0", vuln) is True

    # Test last_affected with local version
    vuln_la = VulnerabilityRecord(
        id="CVE-2024-9999",
        package_name="testpkg",
        affected_versions=[],
        ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"last_affected": "1.2.3+local.1"}]}],
    )
    # 1.2.3 is affected (1.0.0 <= 1.2.3 <= 1.2.3)
    assert is_version_affected("1.2.3", vuln_la) is True
    # 1.2.4 is NOT affected
    assert is_version_affected("1.2.4", vuln_la) is False


def test_epss_cache_fresh(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """EPSS CSV downloaded today is used from cache"""
    cache_file = tmp_path / "epss_scores-current.csv.gz"
    # Create a fake GZIP CSV
    with gzip.open(cache_file, "wt") as f:
        f.write("cve,epss,percentile\n")
        f.write("CVE-2024-0001,0.95,0.99\n")

    # Ensure mtime is today
    # (default is now)

    scores = load_epss_scores(tmp_path)
    assert scores["CVE-2024-0001"] == 0.95


def test_cross_ecosystem_advisories_loaded(tmp_path: Path) -> None:
    """Non-PyPI ecosystem advisories attach as signals"""
    zip_p = tmp_path / "osv_cross.zip"
    vuln_data = {
        "id": "GO-2024-0001",
        "affected": [
            {
                "package": {"ecosystem": "Go", "name": "vulnpkg"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            }
        ],
    }

    with zipfile.ZipFile(zip_p, "w") as z:
        z.writestr("vuln.json", json.dumps(vuln_data))

    index = load_osv_index(zip_p)
    assert "vulnpkg" in index.by_package
    assert index.by_package["vulnpkg"][0].is_cross_ecosystem is True
