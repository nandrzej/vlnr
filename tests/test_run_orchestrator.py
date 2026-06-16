import json
from pathlib import Path

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
