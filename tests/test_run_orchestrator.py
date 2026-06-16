import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from vlnr.__main__ import build_initial_state


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
