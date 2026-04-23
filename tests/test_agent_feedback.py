import unittest
from unittest.mock import MagicMock, patch
from vlnr.agent import AgentLoop
from vlnr.agent_models import AgentState, AgentAction
from vlnr.vuln_models import PackageFindings, Slice, PoCData, TriageInfo


class TestAgentFeedback(unittest.TestCase):
    def setUp(self) -> None:
        self.mock_llm = MagicMock()
        self.agent = AgentLoop(llm_client=self.mock_llm)
        self.initial_state = AgentState(max_iterations=5, budget_remaining=10.0)

    @patch("vlnr.agent.process_package")
    def test_scan_and_stop_loop(self, mock_process: MagicMock) -> None:
        # Setup mock findings
        mock_findings = PackageFindings(
            package={"name": "mock-pkg", "version": "1.0.0"}, sinks=[], stats={"num_sinks_total": 0}
        )
        mock_process.return_value = mock_findings

        # Sequence of LLM actions
        self.mock_llm.completion.side_effect = [
            AgentAction(action="scan_package", package_name="mock-pkg", reasoning="Initial scan"),
            AgentAction(action="stop", reasoning="Done"),
        ]

        # Run the loop
        # Using a temporary file for state path to avoid side effects
        with patch.object(AgentState, "save_to_json"):
            self.agent.run(self.initial_state, state_path="test_session.json")

        # Verify state updates
        self.assertIn("mock-pkg", self.initial_state.scanned_packages)
        self.assertEqual(len(self.initial_state.findings), 1)
        self.assertEqual(len(self.initial_state.history), 2)

        # Verify history entries
        self.assertEqual(self.initial_state.history[0]["action"]["action"], "scan_package")
        self.assertTrue(self.initial_state.history[0]["observation"]["success"])
        self.assertEqual(self.initial_state.history[1]["action"]["action"], "stop")

    @patch("vlnr.agent.generate_poc")
    @patch("vlnr.agent.validate_poc_in_container")
    def test_generate_and_validate_poc(self, mock_validate: MagicMock, mock_generate: MagicMock) -> None:
        # Setup state with a slice needing PoC
        target_slice = Slice(
            slice_id="slice-123",
            package="mock-pkg",
            version="1.0.0",
            category=["rce"],
            sink_api="os.system",
            static_class="suspicious",
            risk_score_static=0.8,
            triage_info=TriageInfo(
                analysis="Looks bad", plausibility=0.9, is_false_positive=False, suggested_cwe="CWE-78"
            ),
            triage_score=0.9,
        )
        self.initial_state.slices.append(target_slice)
        self.initial_state.scanned_packages.append("mock-pkg")

        # Mock PoC generation
        mock_poc = PoCData(exploit_code="print('pwned')", prerequisites=[], verification_steps="run it")
        mock_generate.return_value = mock_poc

        # Mock Validation
        mock_validate.return_value = MagicMock(status="success")
        mock_validate.return_value.model_dump.return_value = {"status": "success"}

        # Sequence of LLM actions
        self.mock_llm.completion.side_effect = [
            AgentAction(action="generate_poc", package_name="mock-pkg", slice_id="slice-123", reasoning="High score"),
            AgentAction(action="validate_poc", package_name="mock-pkg", slice_id="slice-123", reasoning="Validate it"),
            AgentAction(action="stop", reasoning="All done"),
        ]

        with patch.object(AgentState, "save_to_json"):
            self.agent.run(self.initial_state, state_path="test_session.json")

        # Verify PoC data was added and updated
        updated_slice = self.initial_state.slices[0]
        self.assertIsNotNone(updated_slice.poc_data)
        if updated_slice.poc_data:
            self.assertEqual(updated_slice.poc_data.verification_steps, "validated: success")
        self.assertEqual(len(self.initial_state.history), 3)


if __name__ == "__main__":
    unittest.main()
