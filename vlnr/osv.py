import json
import zipfile
import gzip
import shutil
from pathlib import Path
from datetime import date

import requests
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from pydantic import ValidationError

from vlnr.models import VulnerabilityIndex, VulnerabilityRecord

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


def load_epss_scores(cache_dir: Path) -> dict[str, float]:
    """
    Load EPSS scores from cache or download fresh.
    Cache path: cache_dir / "epss_scores-current.csv.gz"
    TTL: today's date.
    """
    cache_path = cache_dir / "epss_scores-current.csv.gz"

    # Check if cache is fresh (mtime date == today)
    needs_download = True
    if cache_path.exists():
        mtime_date = date.fromtimestamp(cache_path.stat().st_mtime)
        if mtime_date == date.today():
            needs_download = False

    if needs_download:
        cache_dir.mkdir(parents=True, exist_ok=True)
        resp = requests.get(EPSS_URL, stream=True)
        resp.raise_for_status()
        with cache_path.open("wb") as f:
            shutil.copyfileobj(resp.raw, f)

    scores: dict[str, float] = {}
    with gzip.open(cache_path, "rt") as f:
        # Skip header lines (first 2 lines usually: version/date, header)
        for line in f:
            if line.startswith("#") or line.startswith("cve,epss"):
                continue
            parts = line.strip().split(",")
            if len(parts) >= 2:
                cve_id = parts[0]
                try:
                    score = float(parts[1])
                    scores[cve_id] = score
                except ValueError:
                    continue
    return scores


def load_osv_index(zip_path: Path, epss_scores: dict[str, float] | None = None) -> VulnerabilityIndex:
    """Load OSV vulnerabilities from ZIP, including cross-ecosystem ones."""
    index = VulnerabilityIndex()
    with zipfile.ZipFile(zip_path, "r") as z:
        for filename in z.namelist():
            if not filename.endswith(".json"):
                continue
            with z.open(filename) as f:
                try:
                    data = json.load(f)

                    # CVSS extraction
                    cvss_score = None
                    severity = data.get("severity", [])
                    for sev in severity:
                        if sev.get("type") == "CVSS_V3":
                            # Extract score from CVSS string or explicit field if present
                            # Most OSVs have "score" in severity if it's there
                            score = sev.get("score")
                            if score is not None:
                                cvss_score = float(score)
                                break

                    # EPSS cross-ref
                    epss_score = None
                    if epss_scores:
                        cve_ids = [data["id"]] + data.get("aliases", [])
                        for cid in cve_ids:
                            if cid in epss_scores:
                                epss_score = epss_scores[cid]
                                break

                    for affected in data.get("affected", []):
                        package = affected.get("package", {})
                        ecosystem = package.get("ecosystem")
                        is_cross = ecosystem != "PyPI"

                        pkg_name = package.get("name", "").lower()
                        if not pkg_name:
                            continue

                        vuln = VulnerabilityRecord(
                            id=data["id"],
                            aliases=data.get("aliases", []),
                            package_name=pkg_name,
                            affected_versions=affected.get("versions", []),
                            ranges=affected.get("ranges", []),
                            cvss_score=cvss_score,
                            epss_score=epss_score,
                            is_cross_ecosystem=is_cross,
                        )

                        if pkg_name not in index.by_package:
                            index.by_package[pkg_name] = []
                        index.by_package[pkg_name].append(vuln)

                except (json.JSONDecodeError, KeyError, ValidationError, ValueError):
                    continue
    return index


def is_version_affected(version_str: str, vuln: VulnerabilityRecord) -> bool:
    """Check if version falls within affected ranges or specific versions."""
    if vuln.is_cross_ecosystem:
        # Cross-ecosystem advisories are informative signals, not hard escalations
        # We don't try to match versions strictly as ecosystems differ
        return False

    try:
        version = Version(version_str)
    except InvalidVersion:
        return False

    # Check explicit version lists first
    if version_str in vuln.affected_versions:
        return True

    # Check semantic ranges
    for r in vuln.ranges:
        if r.get("type") != "ECOSYSTEM":
            continue

        events = r.get("events", [])
        introduced = None
        fixed = None
        last_affected = None

        for event in events:
            if "introduced" in event:
                introduced = event["introduced"]
            elif "fixed" in event:
                fixed = event["fixed"]
            elif "last_affected" in event:
                last_affected = event["last_affected"]

        spec_parts = []
        if introduced and introduced != "0":
            spec_parts.append(f">={_normalize_version_for_specifier(introduced)}")
        if fixed:
            spec_parts.append(f"<{_normalize_version_for_specifier(fixed)}")
        if last_affected:
            spec_parts.append(f"<={_normalize_version_for_specifier(last_affected)}")

        if not spec_parts:
            continue

        try:
            spec = SpecifierSet(",".join(spec_parts))
            if version in spec:
                return True
        except (InvalidSpecifier, ValueError):
            continue

    return False


def _normalize_version_for_specifier(v_str: str) -> str:
    try:
        return str(Version(v_str).public)
    except InvalidVersion:
        return v_str


def get_vulnerability_ids(vulns: list[VulnerabilityRecord]) -> dict[str, list[str]]:
    """Group IDs by type: {osv_ids: [...], pysec_ids: [...], ghsa_ids: [...]}"""
    result: dict[str, list[str]] = {"osv_ids": [], "pysec_ids": [], "ghsa_ids": []}

    for v in vulns:
        result["osv_ids"].append(v.id)
        for alias in v.aliases:
            if alias.startswith("PYSEC-"):
                result["pysec_ids"].append(alias)
            elif alias.startswith("GHSA-"):
                result["ghsa_ids"].append(alias)

    # Remove duplicates
    for key in result:
        result[key] = sorted(list(set(result[key])))

    return result
