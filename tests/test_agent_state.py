import os
import tempfile
from vlnr.agent_models import AgentState, AgentAction, AgentObservation


def test_agent_state_serialization() -> None:
    # Setup some test data
    state = AgentState(
        scanned_packages=["test-pkg"],
        findings=[],
        slices=[],
        iterations=1,
        max_iterations=10,
        budget_remaining=0.95,
        history=[
            {
                "action": AgentAction(
                    action="scan_package",
                    package_name="test-pkg",
                    reasoning="Initial scan",
                ).model_dump(),
                "observation": AgentObservation(success=True, data={"found": 0}).model_dump(),
            }
        ],
    )

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        # Save
        state.save_to_json(tmp_path)
        assert os.path.exists(tmp_path)

        # Load
        loaded_state = AgentState.load_from_json(tmp_path)

        # Verify
        assert loaded_state.scanned_packages == state.scanned_packages
        assert loaded_state.iterations == state.iterations
        assert loaded_state.max_iterations == state.max_iterations
        assert loaded_state.budget_remaining == state.budget_remaining
        assert loaded_state.history == state.history
        assert len(loaded_state.history) == 1
        assert loaded_state.history[0]["action"]["action"] == "scan_package"

    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_agent_state_empty_history() -> None:
    state = AgentState(max_iterations=5, budget_remaining=1.0)
    assert state.history == []
    assert state.scanned_packages == []


def test_agent_action_optional_fields() -> None:
    action = AgentAction(action="stop", reasoning="Done")
    assert action.package_name is None
    assert action.slice_id is None
