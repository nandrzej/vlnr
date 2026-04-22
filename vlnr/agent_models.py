from typing import Literal, Optional, Any
from pydantic import BaseModel, Field
from vlnr.vuln_models import PackageFindings, Slice
import os


class AgentAction(BaseModel):
    action: Literal["scan_package", "generate_poc", "validate_poc", "stop"]
    package_name: Optional[str] = None
    slice_id: Optional[str] = None
    reasoning: str


class AgentObservation(BaseModel):
    success: bool
    data: Any
    message: Optional[str] = None


class AgentState(BaseModel):
    scanned_packages: list[str] = Field(default_factory=list)
    findings: list[PackageFindings] = Field(default_factory=list)
    slices: list[Slice] = Field(default_factory=list)
    iterations: int = 0
    max_iterations: int
    budget_remaining: float
    history: list[dict[str, Any]] = Field(default_factory=list)

    def save_to_json(self, path: str) -> None:
        """Saves the agent state to a JSON file."""
        directory = os.path.dirname(os.path.abspath(path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.model_dump_json(indent=2))

    @classmethod
    def load_from_json(cls, path: str) -> "AgentState":
        """Loads the agent state from a JSON file."""
        if not os.path.exists(path):
            raise FileNotFoundError(f"State file not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            return cls.model_validate_json(f.read())
