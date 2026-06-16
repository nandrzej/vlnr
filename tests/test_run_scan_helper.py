from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vlnr.vuln_cli import run_scan


@pytest.fixture
def candidates_file(tmp_path: Path) -> Path:
    p = tmp_path / "candidates.json"
    p.write_text(json.dumps([
        {"name": "pkg-a", "version": "1.0.0"},
        {"name": "pkg-b", "version": "2.0.0"},
    ]))
    return p


def test_run_scan_writes_global_index(tmp_path: Path, candidates_file: Path) -> None:
    out_dir = tmp_path / "out"
    mock_findings = MagicMock()
    mock_findings.stats = {"num_sinks_total": 0, "num_obvious_vuln": 0, "num_bandit_hits": 0}
    with patch("vlnr.vuln_cli.process_package", return_value=mock_findings):
        run_scan(
            candidates_path=candidates_file,
            out_dir=out_dir,
            max_packages=0,
            max_files_per_pkg=0,
            llm_client=None,
            generate_pocs=False,
        )
    written = json.loads((out_dir / "all-findings-index.json").read_text())
    assert written == [
        {"package": "pkg-a", "version": "1.0.0", "stats": mock_findings.stats},
        {"package": "pkg-b", "version": "2.0.0", "stats": mock_findings.stats},
    ]


def test_run_scan_respects_max_packages(tmp_path: Path, candidates_file: Path) -> None:
    out_dir = tmp_path / "out"
    with patch("vlnr.vuln_cli.process_package", return_value=MagicMock(stats={})) as m:
        run_scan(
            candidates_path=candidates_file,
            out_dir=out_dir,
            max_packages=1,
            max_files_per_pkg=0,
            llm_client=None,
            generate_pocs=False,
        )
    assert m.call_count == 1


def test_run_scan_creates_out_dir(tmp_path: Path, candidates_file: Path) -> None:
    out_dir = tmp_path / "nested" / "deeper" / "out"
    with patch("vlnr.vuln_cli.process_package", return_value=None):
        run_scan(
            candidates_path=candidates_file,
            out_dir=out_dir,
            max_packages=0,
            max_files_per_pkg=0,
            llm_client=None,
            generate_pocs=False,
        )
    assert out_dir.is_dir()
