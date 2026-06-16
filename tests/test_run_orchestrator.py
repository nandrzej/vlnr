import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from typer.testing import CliRunner

from vlnr.__main__ import app, build_initial_state

runner = CliRunner()


FIXTURES = Path(__file__).parent / "fixtures" / "run_orchestrator"


@pytest.fixture
def candidates() -> list[dict]:
    return json.loads((FIXTURES / "candidates.json").read_text())


def test_build_initial_state_normal_flow(candidates: list[dict]) -> None:
    state = build_initial_state(
        out_dir=FIXTURES,
        candidates=candidates,
        max_iterations=5,
        budget=10.0,
    )
    assert state.scanned_packages == ["pkg-a", "pkg-b", "pkg-c"]
    assert state.candidate_pool == ["pkg-a", "pkg-b", "pkg-c"]
    assert len(state.findings) == 2  # pkg-a and pkg-b; pkg-c missing
    assert len(state.slices) == 1  # pkg-a's one slice
    assert state.max_iterations == 5
    assert state.budget_remaining == 10.0


def test_build_initial_state_skip_scan(candidates: list[dict]) -> None:
    state = build_initial_state(
        out_dir=FIXTURES,
        candidates=candidates,
        max_iterations=5,
        budget=10.0,
        scanned=[],
    )
    assert state.scanned_packages == []
    assert state.candidate_pool == ["pkg-a", "pkg-b", "pkg-c"]
    assert state.findings == []
    assert state.slices == []


def test_run_stage_returns_on_success() -> None:
    from vlnr.__main__ import _run_stage

    fn = MagicMock(return_value=None)
    _run_stage("discover", fn, "arg1", key="value")
    fn.assert_called_once_with("arg1", key="value")


def test_run_stage_exits_one_on_exception(capsys: pytest.CaptureFixture[str]) -> None:
    from typer import Exit

    from vlnr.__main__ import _run_stage

    def boom() -> None:
        raise ValueError("kaboom")

    with pytest.raises(Exit) as exc_info:
        _run_stage("scan", boom)
    assert exc_info.value.exit_code == 1
    err = capsys.readouterr().err
    assert "Stage scan failed" in err
    assert "ValueError" in err
    assert "kaboom" in err


def test_run_help() -> None:
    result = runner.invoke(app, ["run", "--help"])
    assert result.exit_code == 0
    assert "--out-dir" in result.stdout


def _stub_candidates(out_dir: Path) -> None:
    (out_dir / "candidates.json").write_text(
        json.dumps(
            [
                {"name": "pkg-a", "version": "1.0.0"},
                {"name": "pkg-b", "version": "1.0.0"},
                {"name": "pkg-c", "version": "1.0.0"},
            ],
        ),
    )


def test_run_skip_scan_skip_agent(tmp_path: Path) -> None:
    out_dir = tmp_path / "results"

    with (
        patch("vlnr.__main__.run_pipeline", new_callable=AsyncMock) as mock_pipeline,
        patch("vlnr.__main__.run_scan") as mock_scan,
        patch("vlnr.__main__.LLMClient") as mock_client,
        patch("vlnr.__main__.AgentLoop") as mock_loop,
    ):

        async def _stub_pipeline(*a, **kw):
            _stub_candidates(out_dir)

        mock_pipeline.side_effect = _stub_pipeline
        result = runner.invoke(
            app,
            [
                "run",
                "--out-dir",
                str(out_dir),
                "--osv-dump",
                "/dev/null",
                "--pypi-json",
                "/dev/null",
                "--skip-scan",
                "--skip-agent",
            ],
        )

    assert result.exit_code == 0, result.stdout + result.stderr
    assert (out_dir / "candidates.json").exists()
    _, kwargs = mock_pipeline.call_args
    assert kwargs["out"] == out_dir / "candidates.json"
    mock_scan.assert_not_called()
    mock_loop.assert_not_called()
    mock_client.assert_not_called()


def test_run_skip_agent_only(tmp_path: Path) -> None:
    out_dir = tmp_path / "results"

    with (
        patch("vlnr.__main__.run_pipeline", new_callable=AsyncMock) as mock_pipeline,
        patch("vlnr.__main__.run_scan") as mock_scan,
        patch("vlnr.__main__.LLMClient") as mock_client,
        patch("vlnr.__main__.AgentLoop") as mock_loop,
    ):

        async def _stub_pipeline(*a, **kw):
            _stub_candidates(out_dir)

        mock_pipeline.side_effect = _stub_pipeline
        mock_scan.side_effect = lambda *a, **kw: (out_dir / "findings").mkdir(parents=True, exist_ok=True)
        result = runner.invoke(
            app,
            [
                "run",
                "--out-dir",
                str(out_dir),
                "--osv-dump",
                "/dev/null",
                "--pypi-json",
                "/dev/null",
                "--skip-agent",
            ],
        )

    assert result.exit_code == 0, result.stdout + result.stderr
    assert (out_dir / "candidates.json").exists()
    assert (out_dir / "findings").exists()
    _, kwargs = mock_pipeline.call_args
    assert kwargs["out"] == out_dir / "candidates.json"
    mock_scan.assert_called_once()
    mock_loop.assert_not_called()
    mock_client.assert_not_called()


def test_run_full_pipeline_calls_agent_loop_with_state(tmp_path: Path) -> None:
    out_dir = tmp_path / "results"

    with (
        patch("vlnr.__main__.run_pipeline", new_callable=AsyncMock) as mock_pipeline,
        patch("vlnr.__main__.run_scan") as mock_scan,
        patch("vlnr.__main__.LLMClient") as mock_client,
        patch("vlnr.__main__.AgentLoop") as mock_loop,
    ):

        async def _stub_pipeline(*a, **kw):
            _stub_candidates(out_dir)

        mock_pipeline.side_effect = _stub_pipeline
        mock_scan.side_effect = lambda *a, **kw: (out_dir / "findings").mkdir(parents=True, exist_ok=True)
        mock_client.return_value = MagicMock()
        mock_loop.return_value = MagicMock()
        result = runner.invoke(
            app,
            [
                "run",
                "--out-dir",
                str(out_dir),
                "--osv-dump",
                "/dev/null",
                "--pypi-json",
                "/dev/null",
            ],
        )

    assert result.exit_code == 0, result.stdout + result.stderr
    mock_loop.assert_called_once()
    state = mock_loop.return_value.run.call_args.args[0]
    assert state.scanned_packages == ["pkg-a", "pkg-b", "pkg-c"]
    assert state.candidate_pool == ["pkg-a", "pkg-b", "pkg-c"]


def test_run_skip_scan_calls_agent_with_empty_scanned(tmp_path: Path) -> None:
    out_dir = tmp_path / "results"

    with (
        patch("vlnr.__main__.run_pipeline", new_callable=AsyncMock) as mock_pipeline,
        patch("vlnr.__main__.run_scan") as mock_scan,
        patch("vlnr.__main__.LLMClient") as mock_client,
        patch("vlnr.__main__.AgentLoop") as mock_loop,
    ):

        async def _stub_pipeline(*a, **kw):
            _stub_candidates(out_dir)

        mock_pipeline.side_effect = _stub_pipeline
        mock_client.return_value = MagicMock()
        mock_loop.return_value = MagicMock()
        result = runner.invoke(
            app,
            [
                "run",
                "--out-dir",
                str(out_dir),
                "--osv-dump",
                "/dev/null",
                "--pypi-json",
                "/dev/null",
                "--skip-scan",
            ],
        )

    assert result.exit_code == 0, result.stdout + result.stderr
    mock_scan.assert_not_called()
    mock_loop.assert_called_once()
    state = mock_loop.return_value.run.call_args.args[0]
    assert state.scanned_packages == []
    assert state.candidate_pool == ["pkg-a", "pkg-b", "pkg-c"]
    assert state.findings == []
    assert state.slices == []


def test_run_mutex_packages_and_pypi_json(tmp_path: Path) -> None:
    out_dir = tmp_path / "results"
    with (
        patch("vlnr.__main__.run_pipeline", new_callable=AsyncMock) as mock_pipeline,
    ):
        result = runner.invoke(
            app,
            [
                "run",
                "--out-dir",
                str(out_dir),
                "--osv-dump",
                "/dev/null",
                "--packages",
                "pkg-a",
                "--pypi-json",
                "/dev/null",
            ],
        )
    assert result.exit_code == 2  # typer.BadParameter
    mock_pipeline.assert_not_called()


def test_run_mutex_neither_packages_nor_pypi_json(tmp_path: Path) -> None:
    out_dir = tmp_path / "results"
    with (
        patch("vlnr.__main__.run_pipeline", new_callable=AsyncMock) as mock_pipeline,
    ):
        result = runner.invoke(
            app,
            [
                "run",
                "--out-dir",
                str(out_dir),
                "--osv-dump",
                "/dev/null",
            ],
        )
    assert result.exit_code == 2
    mock_pipeline.assert_not_called()
