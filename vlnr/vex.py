"""OpenVEX document generation for vulnerability findings."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vlnr.models import VexStatus

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"


def _derive_vulnerability_id(finding: dict[str, Any], vuln_id: str | None) -> str:
    if vuln_id:
        return vuln_id
    finding_id: str = finding.get("id", "")
    if finding_id:
        return finding_id
    osv_ids: list[str] = finding.get("osv_ids", [])
    if osv_ids and osv_ids[0]:
        return osv_ids[0]
    return "unknown"


def _derive_product_id(finding: dict[str, Any], product_id: str | None) -> str:
    if product_id:
        return product_id
    package_name: str = finding.get("package_name", "unknown")
    version: str = finding.get("version", "")
    if version:
        return f"pkg:pypi/{package_name}@{version}"
    return f"pkg:pypi/{package_name}"


def generate_vex_document(
    finding: dict[str, Any],
    vex_status: VexStatus,
    product_id: str | None = None,
    vulnerability_id: str | None = None,
) -> dict[str, Any]:
    """Generate an OpenVEX document for a vulnerability finding.

    Returns a JSON-serializable dict conforming to OpenVEX v0.2.0.
    """
    vuln_id = _derive_vulnerability_id(finding, vulnerability_id)
    prod_id = _derive_product_id(finding, product_id)

    statement: dict[str, Any] = {
        "vulnerability": vuln_id,
        "products": [prod_id],
        "status": vex_status,
    }

    if vex_status == "not_affected":
        statement["justification"] = "vulnerable_code_not_in_execute_path"

    return {
        "@context": OPENVEX_CONTEXT,
        "id": f"vex:{uuid.uuid4()}",
        "author": "vlnr",
        "role": "Security Researcher",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": 1,
        "statements": [statement],
    }


def write_vex_document(vex_doc: dict[str, Any], output_path: str | Path) -> Path:
    """Write a VEX document as JSON to the given path.

    Creates parent directories if needed. Returns the resolved Path.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(vex_doc, indent=2))
    return path
