from pathlib import Path
import json
import zipfile
from vlnr.osv import load_osv_index, is_version_affected, get_vulnerability_ids
from vlnr.models import VulnerabilityRecord


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
