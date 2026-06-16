from unittest.mock import MagicMock

from vlnr.agent import AgentLoop
from vlnr.agent_models import AgentAction, AgentState


def _build_loop() -> AgentLoop:
    return AgentLoop(MagicMock(), out_dir="out")


# Note: `decide_action` mutates `state.budget_remaining` AFTER building the
# user_prompt (`vlnr/agent.py:106`). These tests do not assert on `state`
# after the call, so a future refactor that reorders or removes the mutation
# would not break them — that is intentional. The assertions below pin the
# prompt text byte-for-byte.


def test_decide_action_prompt_omits_candidate_line_when_none() -> None:
    loop = _build_loop()
    state = AgentState(max_iterations=5, budget_remaining=10.0)  # candidate_pool=None
    expected = (
        "Current State Summary:\n"
        "- Scanned Packages: None\n"
        "- Total Findings: 0\n"
        "- Slices needing PoC: []\n"
        "- Slices with PoC needing validation: []\n"
        "- Last Action Result: None\n"
        "- Iterations: 0/5\n"
        "- Budget Remaining: $10.00\n\n"
        "Determine the next action."
    )

    captured: dict[str, str] = {}

    def fake_completion(messages, response_model, tier):  # type: ignore[no-untyped-def]
        captured["user_prompt"] = messages[1]["content"]
        return AgentAction(action="stop", reasoning="x")

    loop.llm_client.completion = fake_completion
    loop.decide_action(state)

    assert captured["user_prompt"] == expected


def test_decide_action_prompt_omits_candidate_line_when_empty() -> None:
    loop = _build_loop()
    state = AgentState(max_iterations=5, budget_remaining=10.0, candidate_pool=[])
    expected = (
        "Current State Summary:\n"
        "- Scanned Packages: None\n"
        "- Total Findings: 0\n"
        "- Slices needing PoC: []\n"
        "- Slices with PoC needing validation: []\n"
        "- Last Action Result: None\n"
        "- Iterations: 0/5\n"
        "- Budget Remaining: $10.00\n\n"
        "Determine the next action."
    )

    captured: dict[str, str] = {}

    def fake_completion(messages, response_model, tier):  # type: ignore[no-untyped-def]
        captured["user_prompt"] = messages[1]["content"]
        return AgentAction(action="stop", reasoning="x")

    loop.llm_client.completion = fake_completion
    loop.decide_action(state)

    assert captured["user_prompt"] == expected


def test_decide_action_prompt_includes_candidate_line_when_populated() -> None:
    loop = _build_loop()
    state = AgentState(
        max_iterations=5,
        budget_remaining=10.0,
        candidate_pool=["pkg-a", "pkg-b", "pkg-c"],
    )

    captured: dict[str, str] = {}

    def fake_completion(messages, response_model, tier):  # type: ignore[no-untyped-def]
        captured["user_prompt"] = messages[1]["content"]
        return AgentAction(action="stop", reasoning="x")

    loop.llm_client.completion = fake_completion
    loop.decide_action(state)

    assert (
        captured["user_prompt"] == "Current State Summary:\n"
        "- Scanned Packages: None\n"
        "- Total Findings: 0\n"
        "- Slices needing PoC: []\n"
        "- Slices with PoC needing validation: []\n"
        "- Last Action Result: None\n"
        "- Iterations: 0/5\n"
        "- Budget Remaining: $10.00\n\n"
        "Determine the next action.\n"
        "- Available candidates (unscanned): pkg-a, pkg-b, pkg-c"
    )
