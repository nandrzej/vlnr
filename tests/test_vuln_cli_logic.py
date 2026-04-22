from typing import Any, Generator, Dict
import os
import pytest
from unittest.mock import MagicMock, patch
from vlnr.vuln_cli import process_package
from vlnr.vuln_models import Slice, DataflowNode


@pytest.fixture
def mock_dependencies() -> Generator[Dict[str, Any], None, None]:
    with (
        patch("vlnr.vuln_cli.fetch_source") as mock_fetch,
        patch("vlnr.vuln_cli.discover_entrypoints") as mock_eps,
        patch("vlnr.vuln_cli.scan_metadata") as mock_metadata,
        patch("vlnr.vuln_cli.get_external_hits") as mock_external,
        patch("vlnr.vuln_cli.ast_taint_scan") as mock_taint,
        patch("vlnr.vuln_cli.ast_bypass_scan") as mock_bypass,
        patch("vlnr.vuln_cli.construct_slices") as mock_construct,
        patch("vlnr.vuln_cli.score_slice") as mock_score,
    ):
        mock_fetch.return_value = MagicMock(local_path="/tmp/fake")
        mock_eps.return_value = []
        mock_metadata.return_value = []
        mock_external.return_value = []
        mock_taint.return_value = []
        mock_bypass.return_value = []
        mock_construct.side_effect = lambda slices, path: slices
        mock_score.return_value = 0.5

        yield {
            "fetch": mock_fetch,
            "metadata": mock_metadata,
            "taint": mock_taint,
            "bypass": mock_bypass,
            "score": mock_score,
        }


def create_mock_slice(slice_id: str, sink_api: str, file: str = "test.py") -> Slice:
    return Slice(
        slice_id=slice_id,
        package="test-pkg",
        version="1.0.0",
        category=["test"],
        sink_api=sink_api,
        static_class="suspicious",
        risk_score_static=0.5,
        dataflow_summary=[DataflowNode(file=file, line=10, expr="test")],
    )


def test_escalation_base64_exec(mock_dependencies: Dict[str, Any], tmp_path: Any) -> None:
    # base64.b64decode + exec
    s1 = create_mock_slice("s1", "base64.b64decode")
    s2 = create_mock_slice("s2", "exec")
    mock_dependencies["taint"].return_value = [s1, s2]

    pkg = {"name": "test-pkg", "version": "1.0.0"}
    out_dir = str(tmp_path / "out")
    os.makedirs(out_dir, exist_ok=True)

    with patch("os.walk") as mock_walk:
        mock_walk.return_value = [("/tmp/fake", [], ["test.py"])]
        # We need builtins.open to work for reading the source file and for writing findings
        real_open = open

        def side_effect(path: Any, *args: Any, **kwargs: Any) -> Any:
            if "/tmp/fake/test.py" in str(path):
                m = MagicMock()
                m.read.return_value = "pass"
                m.__enter__.return_value = m
                return m
            return real_open(path, *args, **kwargs)

        with patch("builtins.open", side_effect=side_effect), patch("ast.parse", return_value=None):
            findings = process_package(pkg, out_dir=out_dir)

    assert findings is not None
    escalated = [s for s in findings.sinks if s.static_class == "obvious_vuln"]
    assert len(escalated) > 0
    assert any("exec" in s.sink_api for s in escalated)
    assert any(s.risk_score_static == 0.95 for s in escalated)
    assert any("Conjunctive Escalation" in s.category for s in escalated)


def test_escalation_network_execution(mock_dependencies: Dict[str, Any], tmp_path: Any) -> None:
    # requests.get + os.system
    s1 = create_mock_slice("s1", "requests.get")
    s2 = create_mock_slice("s2", "os.system")
    mock_dependencies["taint"].return_value = [s1, s2]

    pkg = {"name": "test-pkg", "version": "1.0.0"}
    out_dir = str(tmp_path / "out")
    os.makedirs(out_dir, exist_ok=True)

    with patch("os.walk") as mock_walk:
        mock_walk.return_value = [("/tmp/fake", [], ["test.py"])]
        real_open = open

        def side_effect(path: Any, *args: Any, **kwargs: Any) -> Any:
            if "/tmp/fake/test.py" in str(path):
                m = MagicMock()
                m.read.return_value = "pass"
                m.__enter__.return_value = m
                return m
            return real_open(path, *args, **kwargs)

        with patch("builtins.open", side_effect=side_effect), patch("ast.parse", return_value=None):
            findings = process_package(pkg, out_dir=out_dir)

    assert findings is not None
    escalated = [s for s in findings.sinks if s.static_class == "obvious_vuln"]
    assert len(escalated) > 0
    assert any("os.system" in s.sink_api for s in escalated)


def test_escalation_metadata_execution(mock_dependencies: Dict[str, Any], tmp_path: Any) -> None:
    # HIGH metadata signal + subprocess.run
    s1 = create_mock_slice("s1", "subprocess.run")
    mock_dependencies["taint"].return_value = [s1]

    from vlnr.vuln_metadata import MetadataSignal

    mock_sig = MetadataSignal(field="Description", pattern_matched="curl", severity="HIGH")

    pkg = {"name": "test-pkg", "version": "1.0.0"}
    out_dir = str(tmp_path / "out")
    os.makedirs(out_dir, exist_ok=True)

    with patch("os.walk") as mock_walk, patch("vlnr.vuln_cli.Path.rglob") as mock_rglob:
        mock_walk.return_value = [("/tmp/fake", [], ["test.py"])]

        # Mock rglob to find a fake .dist-info and then mock scan_metadata to return signals
        mock_dist_info = MagicMock()
        mock_dist_info.is_dir.return_value = True
        mock_rglob.return_value = [mock_dist_info]
        mock_dependencies["metadata"].return_value = [mock_sig]

        real_open = open

        def side_effect(path: Any, *args: Any, **kwargs: Any) -> Any:
            if "/tmp/fake/test.py" in str(path):
                m = MagicMock()
                m.read.return_value = "pass"
                m.__enter__.return_value = m
                return m
            return real_open(path, *args, **kwargs)

        with patch("builtins.open", side_effect=side_effect), patch("ast.parse", return_value=None):
            findings = process_package(pkg, out_dir=out_dir)

    assert findings is not None
    escalated = [s for s in findings.sinks if s.static_class == "obvious_vuln"]
    assert len(escalated) > 0
    assert any("subprocess" in s.sink_api for s in escalated)


def test_no_escalation_single_signal(mock_dependencies: Dict[str, Any], tmp_path: Any) -> None:
    # Single os.system without other signals
    s1 = create_mock_slice("s1", "os.system")
    mock_dependencies["taint"].return_value = [s1]

    pkg = {"name": "test-pkg", "version": "1.0.0"}
    out_dir = str(tmp_path / "out")
    os.makedirs(out_dir, exist_ok=True)

    with patch("os.walk") as mock_walk:
        mock_walk.return_value = [("/tmp/fake", [], ["test.py"])]
        real_open = open

        def side_effect(path: Any, *args: Any, **kwargs: Any) -> Any:
            if "/tmp/fake/test.py" in str(path):
                m = MagicMock()
                m.read.return_value = "pass"
                m.__enter__.return_value = m
                return m
            return real_open(path, *args, **kwargs)

        with patch("builtins.open", side_effect=side_effect), patch("ast.parse", return_value=None):
            findings = process_package(pkg, out_dir=out_dir)

    assert findings is not None
    escalated = [s for s in findings.sinks if s.static_class == "obvious_vuln"]
    assert len(escalated) == 0
    # Should stay suspicious (as initialized in create_mock_slice)
    assert all(s.static_class == "suspicious" for s in findings.sinks)
