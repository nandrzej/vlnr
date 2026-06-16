from pathlib import Path

from vlnr.agent_models import AgentState


def test_agent_state_default_candidate_pool_is_none() -> None:
    state = AgentState(max_iterations=5, budget_remaining=10.0)
    assert state.candidate_pool is None


def test_agent_state_candidate_pool_round_trip(tmp_path: Path) -> None:
    state = AgentState(
        max_iterations=5,
        budget_remaining=10.0,
        candidate_pool=["pkg-a", "pkg-b", "pkg-c"],
    )
    path = str(tmp_path / "agent_state.json")
    state.save_to_json(path)
    loaded = AgentState.load_from_json(path)
    assert loaded.candidate_pool == ["pkg-a", "pkg-b", "pkg-c"]


def test_agent_state_loads_without_candidate_pool_field() -> None:
    """Backwards compat: old JSON state files without the field must load."""
    import os
    import tempfile

    legacy_json = (
        '{"scanned_packages":[],"findings":[],"slices":[],'
        '"iterations":0,"max_iterations":5,"budget_remaining":10.0,"history":[]}'
    )
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write(legacy_json)
        path = f.name
    try:
        loaded = AgentState.load_from_json(path)
        assert loaded.candidate_pool is None
    finally:
        os.unlink(path)
