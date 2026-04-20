import os
import shutil
import tempfile
from unittest.mock import patch
from vlnr.vuln_cli import process_package
from vlnr.vuln_models import ToolHit


def test_external_hit_creates_slice() -> None:
    # Mocking fetch_source to return a temp directory with one file
    temp_dir = tempfile.mkdtemp()
    os.makedirs(os.path.join(temp_dir, "src"))
    file_path = os.path.join(temp_dir, "src", "vuln.py")
    with open(file_path, "w") as f:
        f.write("import os\nos.system(input())")

    # Use patches
    with (
        patch("vlnr.vuln_cli.fetch_source") as mock_source,
        patch("vlnr.vuln_cli.cleanup_source"),
        patch("vlnr.vuln_cli.discover_entrypoints", return_value=[]),
        patch("vlnr.vuln_cli.get_external_hits") as mock_hits,
        patch("vlnr.vuln_cli.ast_taint_scan", return_value=[]),
        patch("vlnr.vuln_cli.score_slice", return_value=0.5),
        patch("vlnr.vuln_cli.construct_slices", side_effect=lambda x, p: x),
    ):
        mock_source.return_value.local_path = temp_dir

        # Mock get_external_hits to return one bandit hit
        hit = ToolHit(
            tool="bandit",
            rule="B602",
            severity="HIGH",
            message="subprocess call with shell=True",
            file="src/vuln.py",
            line=2,
        )
        mock_hits.return_value = [hit]

        pkg = {"name": "testpkg", "version": "1.0.0", "repo_url": "http://example.com"}

        with tempfile.TemporaryDirectory() as out_dir:
            findings = process_package(pkg, out_dir)

            assert findings is not None
            assert findings.stats["num_sinks_total"] == 1
            # The slice should have been created from the hit
            s = findings.sinks[0]
            assert s["static_class"] == "suspicious"
            assert s["tool_hits"][0]["rule"] == "B602"
            assert s["dataflow_summary"][0]["line"] == 2

    shutil.rmtree(temp_dir)
