import pytest
from unittest.mock import MagicMock, patch
from vlnr.agent import AgentLoop
from vlnr.agent_models import AgentState, AgentAction
from vlnr.vuln_models import PackageFindings, Slice, TriageInfo, ToolHit
from vlnr.vuln_reasoner import PoCResult
from vlnr.vuln_validate import ValidationResult


@pytest.fixture
def mock_llm_client() -> MagicMock:
    client = MagicMock()
    return client


@pytest.fixture
def initial_state() -> AgentState:
    return AgentState(
        max_iterations=5,
        budget_remaining=10.0,
    )


def test_agent_e2e_dry_run(mock_llm_client: MagicMock, initial_state: AgentState) -> None:
    """
    Tests a full agent cycle: scan -> generate_poc -> validate_poc -> stop.
    All heavy lifting is mocked.
    """
    loop = AgentLoop(llm_client=mock_llm_client)

    pkg_name = "vulnerable-package"
    slice_id = "test-slice-123"

    # Define the sequence of actions the LLM will return
    actions = [
        AgentAction(action="scan_package", package_name=pkg_name, reasoning="Let's scan this suspicious package."),
        AgentAction(
            action="generate_poc",
            package_name=pkg_name,
            slice_id=slice_id,
            reasoning="Found a high-confidence slice, let's generate a PoC.",
        ),
        AgentAction(
            action="validate_poc",
            package_name=pkg_name,
            slice_id=slice_id,
            reasoning="Validation is required to confirm the exploit.",
        ),
        AgentAction(action="stop", reasoning="Mission accomplished."),
    ]
    mock_llm_client.completion.side_effect = actions

    # Mock process_package
    mock_findings = PackageFindings(
        package={"name": pkg_name, "version": "1.0.0"},
        sinks=[
            Slice(
                slice_id=slice_id,
                package=pkg_name,
                version="1.0.0",
                category=["RCE"],
                sink_api="os.system",
                static_class="suspicious",
                risk_score_static=0.8,
                triage_info=TriageInfo(
                    analysis="Plausible RCE", plausibility=0.9, is_false_positive=False, suggested_cwe="CWE-78"
                ),
                triage_score=0.9,
                tool_hits=[
                    ToolHit(
                        tool="bandit",
                        rule="B605",
                        severity="HIGH",
                        message="Possible shell injection",
                        file="main.py",
                        line=10,
                    )
                ],
            )
        ],
        stats={"num_sinks_total": 1, "num_obvious_vuln": 0, "num_bandit_hits": 1},
    )

    # Mock generate_poc (vlnr.agent calls vlnr.vuln_reasoner.generate_poc)
    mock_poc_result = PoCResult(
        exploit_code="print('pwned')",
        prerequisites=[],
        verification_steps="Check if 'pwned' is printed",
        suggested_cwe="CWE-78",
    )

    # Mock validate_poc_in_container
    mock_validation_result = ValidationResult(
        status="Runtime_Reachable", exit_code=0, stdout="pwned", stderr="", expected_output_matched=True
    )

    with (
        patch("vlnr.agent.process_package", return_value=mock_findings),
        patch("vlnr.agent.generate_poc", return_value=mock_poc_result),
        patch("vlnr.agent.validate_poc_in_container", return_value=mock_validation_result),
    ):
        loop.run(initial_state, state_path="test_agent_session.json")

    # Verify final state
    assert pkg_name in initial_state.scanned_packages
    assert len(initial_state.findings) == 1
    assert len(initial_state.slices) == 1

    target_slice = initial_state.slices[0]
    assert target_slice.slice_id == slice_id
    assert target_slice.poc_data is not None
    assert target_slice.poc_data.exploit_code == "print('pwned')"
    assert target_slice.poc_data.verification_steps == "validated: Runtime_Reachable"

    # 1. Decide scan -> Dispatch -> Update -> iterations=1
    # 2. Decide generate -> Dispatch -> Update -> iterations=2
    # 3. Decide validate -> Dispatch -> Update -> iterations=3
    # 4. Decide stop -> break -> iterations remains 3
    assert initial_state.iterations == 3

    # Check history
    assert len(initial_state.history) == 4
    assert initial_state.history[0]["action"]["action"] == "scan_package"
    assert initial_state.history[1]["action"]["action"] == "generate_poc"
    assert initial_state.history[2]["action"]["action"] == "validate_poc"
    assert initial_state.history[3]["action"]["action"] == "stop"
