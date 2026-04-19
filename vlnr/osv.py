import json
import zipfile
from pathlib import Path

import yaml
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from pydantic import ValidationError

from vlnr.models import VulnerabilityIndex, VulnerabilityRecord


def load_pypa_advisory_db(repo_path: Path, index: VulnerabilityIndex) -> None:
    """Load vulnerabilities from a local clone of pypa/advisory-database."""
    vulns_dir = repo_path / "vulns"
    if not vulns_dir.exists():
        return

    for yaml_path in vulns_dir.rglob("*.yaml"):
        with yaml_path.open("r", encoding="utf-8") as f:
            try:
                data = yaml.safe_load(f)
                if not isinstance(data, dict):
                    continue
                vuln = VulnerabilityRecord(
                    id=data.get("id", ""),
                    aliases=data.get("aliases", []),
                    package_name="",
                    affected_versions=[],
                    ranges=[],
                )

                for affected in data.get("affected", []):
                    package = affected.get("package", {})
                    if package.get("ecosystem") != "PyPI":
                        continue

                    pkg_name = package.get("name", "").lower()
                    if not pkg_name:
                        continue

                    vuln.package_name = pkg_name
                    vuln.affected_versions = affected.get("versions", [])
                    vuln.ranges = affected.get("ranges", [])

                    if pkg_name not in index.by_package:
                        index.by_package[pkg_name] = []
                    index.by_package[pkg_name].append(vuln.model_copy())
            except yaml.YAMLError, KeyError, ValidationError:
                continue


def load_osv_index(zip_path: Path) -> VulnerabilityIndex:
    """Load OSV PyPI vulnerabilities from ZIP."""
    index = VulnerabilityIndex()
    with zipfile.ZipFile(zip_path, "r") as z:
        for filename in z.namelist():
            if not filename.endswith(".json"):
                continue
            with z.open(filename) as f:
                try:
                    data = json.load(f)
                    vuln = VulnerabilityRecord(
                        id=data["id"],
                        aliases=data.get("aliases", []),
                        package_name="",  # Will fill below
                        affected_versions=[],
                        ranges=[],
                    )

                    for affected in data.get("affected", []):
                        package = affected.get("package", {})
                        if package.get("ecosystem") != "PyPI":
                            continue

                        pkg_name = package.get("name", "").lower()
                        if not pkg_name:
                            continue

                        # Update vuln record with specific package info
                        vuln.package_name = pkg_name
                        vuln.affected_versions = affected.get("versions", [])
                        vuln.ranges = affected.get("ranges", [])

                        if pkg_name not in index.by_package:
                            index.by_package[pkg_name] = []
                        index.by_package[pkg_name].append(vuln.model_copy())

                except json.JSONDecodeError, KeyError, ValidationError:
                    continue
    return index


def _normalize_version_for_specifier(v_str: str) -> str:
    """Normalize version string for packaging.specifiers.Specifier.

    Specifiers do not allow local versions (PEP 440).
    We extract the public part.
    """
    try:
        return str(Version(v_str).public)
    except InvalidVersion:
        return v_str


def is_version_affected(version_str: str, vuln: VulnerabilityRecord) -> bool:
    """Check if version falls within affected ranges or specific versions."""
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
            # For simplicity, we mostly care about ecosystem versions
            # but we can also handle SEMVER if needed.
            # PyPI uses PEP 440, which ECOSYSTEM covers.
            continue

        events = r.get("events", [])
        # We need a specifier string to use SpecifierSet
        # OSV ranges are [introduced, fixed/last_affected]
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
        except InvalidSpecifier, ValueError:
            continue

    return False


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
