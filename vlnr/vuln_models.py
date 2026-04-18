from pydantic import BaseModel, Field
from typing import Literal, Any


class ToolHit(BaseModel):
    tool: str  # "bandit", "ruff", "semgrep"
    rule: str  # "S602", "B602"
    severity: str  # "HIGH", "ERROR"
    message: str
    file: str
    line: int


class TaintInfo(BaseModel):
    tainted_args: list[str] = Field(default_factory=list)
    source_types: list[str] = Field(default_factory=list)
    sanitizers: list[str] = Field(default_factory=list)


class DataflowNode(BaseModel):
    file: str
    line: int
    expr: str


class Slice(BaseModel):
    slice_id: str
    package: str
    version: str
    category: list[str]
    sink_api: str
    static_class: Literal["obvious_vuln", "suspicious", "benign"]
    risk_score_static: float
    cwe_candidates: list[str] = Field(default_factory=list)
    source_types: list[str] = Field(default_factory=list)
    tainted_args: list[str] = Field(default_factory=list)
    sanitizers: list[str] = Field(default_factory=list)
    entrypoint: dict[str, Any] | None = None
    code_snippets: list[dict[str, Any]] = Field(default_factory=list)
    dataflow_summary: list[DataflowNode] = Field(default_factory=list)
    tool_hits: list[ToolHit] = Field(default_factory=list)


class PackageFindings(BaseModel):
    package: dict[str, Any]
    sinks: list[dict[str, Any]]  # Summary of slices
    stats: dict[str, Any]  # num_sinks_total, num_obvious_vuln, num_bandit_hits
