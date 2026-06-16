from unittest.mock import patch

import pytest


def test_find_candidates_shim_warns_deprecation() -> None:
    from vlnr._legacy import find_candidates_shim

    with (
        patch("vlnr.cli.app") as mock_app,
        pytest.warns(DeprecationWarning, match="poc-find-candidates"),
    ):
        find_candidates_shim()
    mock_app.assert_called_once()


def test_scan_shim_warns_deprecation() -> None:
    from vlnr._legacy import scan_shim

    with (
        patch("typer.run") as mock_run,
        pytest.warns(DeprecationWarning, match="poc-scan-vulnerabilities"),
    ):
        scan_shim()
    mock_run.assert_called_once()
