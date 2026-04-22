import logging

from vlnr.agent_models import AgentAction, AgentObservation, AgentState
from vlnr.llm import LLMClient, LLMTier
from vlnr.vuln_cli import process_package
from vlnr.vuln_reasoner import generate_poc
from vlnr.vuln_validate import validate_poc_in_container
from vlnr.vuln_models import PoCData

logger = logging.getLogger(__name__)


class AgentLoop:
    def __init__(self, llm_client: LLMClient) -> None:
        self.llm_client = llm_client

    def run(self, initial_state: AgentState, state_path: str = "agent_session.json") -> None:
        """Main orchestration loop."""
        state = initial_state
        logger.info(f"Starting agent loop. Max iterations: {state.max_iterations}")

        while state.iterations < state.max_iterations and state.budget_remaining > 0:
            logger.info(f"Iteration {state.iterations + 1}/{state.max_iterations}")
            
            action = self.decide_action(state)
            
            if action.action == "stop":
                logger.info(f"Agent decided to stop. Reason: {action.reasoning}")
                state.history.append({
                    "iteration": state.iterations,
                    "action": action.model_dump(),
                    "observation": {"success": True, "data": None, "message": "Stopped by agent"}
                })
                break

            observation = self.dispatch_action(action, state)
            self._update_state(state, action, observation)
            
            state.iterations += 1
            state.save_to_json(state_path)
            logger.info(f"State saved to {state_path}")

        logger.info("Agent loop finished.")

    def _estimate_cost(self, tier: LLMTier) -> float:
        """Estimates cost based on LLM tier."""
        costs = {
            LLMTier.TIER_1: 0.05,
            LLMTier.TIER_2: 0.01,
            LLMTier.TIER_3: 0.002,
        }
        return costs.get(tier, 0.0)

    def decide_action(self, state: AgentState) -> AgentAction:
        """Calls LLM to choose the next action."""
        system_prompt = (
            "You are an autonomous security agent specializing in finding and validating vulnerabilities in Python packages. "
            "Your goal is to identify high-risk code patterns, generate proof-of-concept (PoC) exploits, and validate them in a secure environment.\n\n"
            "Available tools:\n"
            "- scan_package(package_name): Downloads and performs static analysis on a package.\n"
            "- generate_poc(package_name, slice_id): Generates a PoC exploit script for a specific vulnerable slice.\n"
            "- validate_poc(package_name, slice_id): Executes the generated PoC in a sandbox to confirm reachability.\n"
            "- stop(reasoning): Terminates the loop when no further actions are productive.\n\n"
            "Guidelines:\n"
            "1. Prioritize packages with high-risk signals.\n"
            "2. Generate PoCs for slices with high triage scores (>0.7).\n"
            "3. ALWAYS validate PoCs immediately after generation to confirm exploitability. Do not move to a new package until validation is complete for high-confidence findings.\n"
            "4. Be efficient with your budget."
        )

        # Summarize state for the prompt
        scanned = ", ".join(state.scanned_packages) or "None"
        findings_count = len(state.findings)
        
        slices_needing_poc = [
            s.slice_id for s in state.slices 
            if s.triage_score and s.triage_score > 0.7 and not s.poc_data
        ]
        slices_needing_validation = [
            s.slice_id for s in state.slices 
            if s.poc_data and s.poc_data.verification_steps == "pending_validation"
        ]

        last_action_summary = "None"
        if state.history:
            last_entry = state.history[-1]
            last_action_summary = (
                f"Action: {last_entry.get('action', {}).get('action', 'unknown')}, "
                f"Success: {last_entry.get('observation', {}).get('success', False)}, "
                f"Message: {last_entry.get('observation', {}).get('message', 'N/A')}"
            )
        
        user_prompt = (
            f"Current State Summary:\n"
            f"- Scanned Packages: {scanned}\n"
            f"- Total Findings: {findings_count}\n"
            f"- Slices needing PoC: {slices_needing_poc}\n"
            f"- Slices with PoC needing validation: {slices_needing_validation}\n"
            f"- Last Action Result: {last_action_summary}\n"
            f"- Iterations: {state.iterations}/{state.max_iterations}\n"
            f"- Budget Remaining: ${state.budget_remaining:.2f}\n\n"
            f"Determine the next action."
        )

        tier = LLMTier.TIER_1
        state.budget_remaining -= self._estimate_cost(tier)
        
        return self.llm_client.completion(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            response_model=AgentAction,
            tier=tier
        )

    def dispatch_action(self, action: AgentAction, state: AgentState) -> AgentObservation:
        """Executes the chosen action."""
        try:
            if action.action == "scan_package":
                if not action.package_name:
                    return AgentObservation(success=False, data=None, message="package_name is required for scan_package")
                
                pkg_info = {"name": action.package_name, "version": "latest"}
                findings = process_package(pkg_info, out_dir="out", llm_client=self.llm_client)
                if findings:
                    return AgentObservation(success=True, data=findings.model_dump())
                return AgentObservation(success=False, data=None, message="Scan failed or no findings")

            elif action.action == "generate_poc":
                if not action.package_name or not action.slice_id:
                    return AgentObservation(success=False, data=None, message="package_name and slice_id are required for generate_poc")
                
                target_slice = next((s for s in state.slices if s.slice_id == action.slice_id), None)
                if not target_slice:
                    return AgentObservation(success=False, data=None, message=f"Slice {action.slice_id} not found in state")
                
                if not target_slice.triage_info:
                    return AgentObservation(success=False, data=None, message=f"Slice {action.slice_id} has no triage info")
                
                vulnerability_context = (
                    f"Analysis: {target_slice.triage_info.analysis}\n"
                    f"Tool Hit: {target_slice.tool_hits[0].message if target_slice.tool_hits else 'N/A'}\n"
                    f"Sink API: {target_slice.sink_api}\n"
                )
                poc_result = generate_poc(
                    action.package_name, 
                    vulnerability_context, 
                    self.llm_client, 
                    target_slice.triage_info.suggested_cwe
                )
                return AgentObservation(success=True, data=poc_result.model_dump())

            elif action.action == "validate_poc":
                if not action.package_name or not action.slice_id:
                    return AgentObservation(success=False, data=None, message="package_name and slice_id are required for validate_poc")
                
                target_slice = next((s for s in state.slices if s.slice_id == action.slice_id), None)
                if not target_slice or not target_slice.poc_data:
                    return AgentObservation(success=False, data=None, message=f"Slice {action.slice_id} or its PoC data not found")
                
                validation_result = validate_poc_in_container(
                    target_slice.poc_data.exploit_code,
                    target_slice.package,
                    target_slice.version
                )
                return AgentObservation(success=True, data=validation_result.model_dump())

            return AgentObservation(success=False, data=None, message=f"Unknown action: {action.action}")
        except Exception as e:
            logger.exception(f"Error dispatching action {action.action}")
            return AgentObservation(success=False, data=None, message=str(e))

    def _update_state(self, state: AgentState, action: AgentAction, observation: AgentObservation) -> None:
        """Merges results into state."""
        state.history.append({
            "iteration": state.iterations,
            "action": action.model_dump(),
            "observation": observation.model_dump()
        })

        if not observation.success:
            return

        if action.action == "scan_package":
            if action.package_name and action.package_name not in state.scanned_packages:
                state.scanned_packages.append(action.package_name)
            
            from vlnr.vuln_models import PackageFindings
            findings_data = observation.data
            findings = PackageFindings.model_validate(findings_data)
            state.findings.append(findings)
            
            # Extend state.slices with new findings
            state.slices.extend(findings.sinks)

        elif action.action == "generate_poc":
            target_slice = next((s for s in state.slices if s.slice_id == action.slice_id), None)
            if target_slice:
                poc_data = PoCData.model_validate(observation.data)
                # Mark as pending validation in verification_steps as a signal for the agent
                poc_data.verification_steps = "pending_validation"
                target_slice.poc_data = poc_data

        elif action.action == "validate_poc":
            target_slice = next((s for s in state.slices if s.slice_id == action.slice_id), None)
            if target_slice and target_slice.poc_data:
                # Update verification_steps with result
                res = observation.data
                status = res.get("status", "unknown")
                target_slice.poc_data.verification_steps = f"validated: {status}"

