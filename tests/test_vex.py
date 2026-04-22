import json
import tempfile
from pathlib import Path

from typing import Any
from vlnr.vex import generate_vex_document, write_vex_document

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
VALID_VEX_STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}


def _sample_finding(**overrides: Any) -> dict[str, Any]:
    """Build a minimal finding dict with sensible defaults."""
    base = {
        "id": "GHSA-xxxx-xxxx",
        "package_name": "test-package",
        "version": "1.0.0",
        "is_false_positive": True,
        "osv_ids": ["OSV-2024-001"],
    }
    base.update(overrides)
    return base


# ── Structure ──────────────────────────────────────────────────────────


def test_generate_vex_basic_structure() -> None:
    """Generated VEX document has required top-level OpenVEX keys."""
    doc = generate_vex_document(_sample_finding(), "not_affected")

    assert doc["@context"] == OPENVEX_CONTEXT
    assert isinstance(doc["id"], str) and doc["id"].startswith("vex:")
    assert isinstance(doc["metadata"], dict)
    for key in ("author", "timestamp", "tool"):
        assert key in doc["metadata"], f"metadata missing '{key}'"
    assert isinstance(doc["statements"], list)
    assert len(doc["statements"]) >= 1


def test_vex_statement_fields() -> None:
    """Each statement contains vulnerability, product, status, and justification."""
    doc = generate_vex_document(_sample_finding(), "not_affected")
    stmt = doc["statements"][0]

    assert "vulnerability" in stmt and "name" in stmt["vulnerability"]
    assert "product" in stmt and "id" in stmt["product"]
    assert "identifiers" in stmt["product"]
    assert stmt["status"] in VALID_VEX_STATUSES
    # 'not_affected' requires justification per OpenVEX
    if stmt["status"] == "not_affected":
        assert "justification" in stmt
        assert "type" in stmt["justification"]


# ── False positive ─────────────────────────────────────────────────────


def test_false_positive_produces_not_affected() -> None:
    """Finding marked is_false_positive yields status='not_affected' with code_not_reachable justification."""
    doc = generate_vex_document(_sample_finding(is_false_positive=True), "not_affected")
    stmt = doc["statements"][0]

    assert stmt["status"] == "not_affected"
    assert "justification" in stmt
    jtype = stmt["justification"]["type"]
    # OpenVEX justification codes for not_affected include code_not_reachable,
    # vulnerable_code_not_in_execute_path, etc.
    assert "code_not_reachable" in jtype or "not_in_execute_path" in jtype or jtype.startswith("impact")


# ── VexStatus coverage ─────────────────────────────────────────────────


def test_vex_status_values_conformant() -> None:
    """Every VexStatus literal maps to a valid statement status."""
    for status in ("affected", "not_affected", "fixed", "under_investigation"):
        doc = generate_vex_document(_sample_finding(), status)
        stmt = doc["statements"][0]
        assert stmt["status"] == status


# ── Serialization ──────────────────────────────────────────────────────


def test_vex_document_serializable() -> None:
    """VEX document round-trips through json.dumps without error."""
    doc = generate_vex_document(_sample_finding(), "affected")
    serialized = json.dumps(doc)
    assert isinstance(serialized, str)
    # Verify it parses back to equivalent structure
    assert json.loads(serialized) == doc


# ── File I/O ───────────────────────────────────────────────────────────


def test_write_vex_document() -> None:
    """write_vex_document writes valid JSON that round-trips correctly."""
    doc = generate_vex_document(_sample_finding(), "fixed")

    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = Path(tmpdir) / "vex.json"
        result_path = write_vex_document(doc, out_path)

        assert result_path.exists()
        with open(result_path) as f:
            loaded = json.load(f)
        assert loaded == doc


# ── Product ID derivation ──────────────────────────────────────────────


def test_vex_product_id_from_finding() -> None:
    """Explicit product_id is used; absent product_id derives pURL from finding."""
    # Explicit product_id
    doc = generate_vex_document(
        _sample_finding(), "affected", product_id="pkg:pypi/custom@2.0.0"
    )
    assert doc["statements"][0]["product"]["id"] == "pkg:pypi/custom@2.0.0"

    # Derived pURL from package_name + version
    doc = generate_vex_document(_sample_finding(), "affected")
    product_id = doc["statements"][0]["product"]["id"]
    assert product_id == "pkg:pypi/test-package@1.0.0"


# ── Vulnerability ID derivation ────────────────────────────────────────


def test_vex_vulnerability_id_from_finding() -> None:
    """Explicit vulnerability_id is used; absent id derives from finding fields."""
    # Explicit vulnerability_id
    doc = generate_vex_document(
        _sample_finding(), "affected", vulnerability_id="CVE-2024-99999"
    )
    assert doc["statements"][0]["vulnerability"]["name"] == "CVE-2024-99999"

    # Derived from finding 'id'
    doc = generate_vex_document(_sample_finding(), "affected")
    assert doc["statements"][0]["vulnerability"]["name"] == "GHSA-xxxx-xxxx"

    # Derived from osv_ids when 'id' is absent
    finding = _sample_finding(id="", osv_ids=["OSV-2024-001"])
    doc = generate_vex_document(finding, "affected")
    assert doc["statements"][0]["vulnerability"]["name"] == "OSV-2024-001"


# ── Edge cases ─────────────────────────────────────────────────────────


def test_vex_finding_with_no_id_fields() -> None:
    """Finding with empty/missing id fields falls back to 'unknown'."""
    finding = {"package_name": "pkg", "version": "1.0.0"}
    doc = generate_vex_document(finding, "under_investigation")
    stmt = doc["statements"][0]
    assert stmt["vulnerability"]["name"] == "unknown"


def test_vex_finding_with_no_version() -> None:
    """Finding without version still produces valid VEX (pURL without @version)."""
    finding = {"id": "GHSA-abc-123", "package_name": "no-ver-pkg"}
    doc = generate_vex_document(finding, "affected")
    product_id = doc["statements"][0]["product"]["id"]
    # pURL without version: pkg:pypi/no-ver-pkg (no @ suffix)
    assert "no-ver-pkg" in product_id
    assert "@context" in doc  # structural integrity preserved


def test_vex_empty_finding() -> None:
    """Empty finding dict still produces valid VEX structure."""
    doc = generate_vex_document({}, "under_investigation")
    assert "@context" in doc
    assert isinstance(doc["statements"], list)
    assert len(doc["statements"]) >= 1
    assert doc["statements"][0]["status"] == "under_investigation"


def test_vex_multiple_docs_same_product_unique_ids() -> None:
    """Multiple VEX documents for the same product have distinct IDs."""
    finding = _sample_finding()
    doc1 = generate_vex_document(finding, "affected")
    doc2 = generate_vex_document(finding, "fixed")

    assert doc1["id"] != doc2["id"]
    assert doc1["statements"][0]["status"] != doc2["statements"][0]["status"]
