from vlnr.vuln_models import PackageFindings, Slice
from vlnr.agent_models import AgentState, AgentAction, AgentObservation
from vlnr.agent import AgentLoop
from vlnr.llm import LLMClient
from unittest.mock import MagicMock


def test_package_findings_uses_slice_objects() -> None:
    # Verify PackageFindings now accepts Slice objects in sinks
    s = Slice(
        slice_id="test-1",
        package="test",
        version="1.0",
        category=["test"],
        sink_api="exec",
        static_class="suspicious",
        risk_score_static=0.5,
    )
    findings = PackageFindings(
        package={"name": "test", "version": "1.0"},
        sinks=[s],
        stats={"num_sinks_total": 1, "num_obvious_vuln": 0, "num_bandit_hits": 0},
    )
    assert isinstance(findings.sinks[0], Slice)
    assert findings.sinks[0].slice_id == "test-1"


def test_agent_loop_update_state_scan_package() -> None:
    llm = MagicMock(spec=LLMClient)
    loop = AgentLoop(llm)
    state = AgentState(max_iterations=5, budget_remaining=10.0)

    s = Slice(
        slice_id="slice-123",
        package="test-pkg",
        version="1.0",
        category=["test"],
        sink_api="exec",
        static_class="suspicious",
        risk_score_static=0.5,
    )
    findings = PackageFindings(
        package={"name": "test-pkg", "version": "1.0"},
        sinks=[s],
        stats={"num_sinks_total": 1, "num_obvious_vuln": 0, "num_bandit_hits": 0},
    )

    action = AgentAction(action="scan_package", package_name="test-pkg", reasoning="test")
    observation = AgentObservation(success=True, data=findings.model_dump())

    loop._update_state(state, action, observation)

    assert "test-pkg" in state.scanned_packages
    assert len(state.findings) == 1
    assert len(state.slices) == 1
    assert state.slices[0].slice_id == "slice-123"


def test_agent_loop_update_state_generate_poc() -> None:
    llm = MagicMock(spec=LLMClient)
    loop = AgentLoop(llm)
    s = Slice(
        slice_id="slice-123",
        package="test-pkg",
        version="1.0",
        category=["test"],
        sink_api="exec",
        static_class="suspicious",
        risk_score_static=0.5,
    )
    state = AgentState(max_iterations=5, budget_remaining=10.0, slices=[s])

    poc_data = {"exploit_code": "print('exploit')", "prerequisites": [], "verification_steps": "steps"}

    action = AgentAction(action="generate_poc", package_name="test-pkg", slice_id="slice-123", reasoning="test")
    observation = AgentObservation(success=True, data=poc_data)

    loop._update_state(state, action, observation)

    assert state.slices[0].poc_data is not None
    assert state.slices[0].poc_data.exploit_code == "print('exploit')"
    assert state.slices[0].poc_data.verification_steps == "pending_validation"
