# vlnr: Autonomous Vulnerability Discovery Pipeline

[![Python 3.14+](https://img.shields.io/badge/python-3.14+-blue.svg)](https://www.python.org/downloads/)
[![Type Checking: MyPy](https://img.shields.io/badge/typing-strict-brightgreen.svg)](https://mypy.readthedocs.io/)
[![Linting: Ruff](https://img.shields.io/badge/lint-ruff-black.svg)](https://github.com/astral-sh/ruff)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

**vlnr** is an autonomous security research framework designed to discover, triage, and validate vulnerabilities across the Python ecosystem. Moving beyond simple static analysis, `vlnr` implements an agentic orchestration loop that combines deep code reasoning with automated exploit validation.

---

## 🧠 Novel Approach: The Agentic Security Loop

The core innovation of `vlnr` is its autonomous "Plan-Scan-Validate" loop. Unlike traditional scanners that stop at a list of potential hits, `vlnr` operates as an agent:

1.  **Semantic Intent Scoring**: Analyzes package metadata and source code to identify "High-Value Targets"—projects handling sensitive data, cryptography, or critical infrastructure.
2.  **Symbolic & Taint Analysis**: Performs deep AST-based scanning and cross-file taint tracking to identify potentially exploitable data flows.
3.  **Tiered Reasoning Triage**: Uses a hierarchy of LLMs to analyze tainted paths, filter out false positives, and determine exploitability.
4.  **Autonomous PoC Validation**: For high-confidence findings, the agent drafts a functional Proof-of-Concept (PoC) exploit and executes it in a transient, isolated Docker container to confirm reachability and impact.

---

## 🛠 Architecture: Tiered LLM Strategy

`vlnr` uses a cost-and-performance optimized model hierarchy. Each tier is mapped to a specific cognitive load within the audit pipeline:

### **Tier 3: Metadata & Rapid Filtering**
*   **Role**: Intent scoring, initial triage, and metadata classification.
*   **Requirements**: Low latency, high throughput.
*   **Suggested Models**: `Qwen 3.5 4B`, `Gemma 4 2B`.

### **Tier 2: Refinement & Contextual Triage**
*   **Role**: Analyzing tainted code slices and reducing static analysis noise.
*   **Requirements**: Strong logical reasoning and moderate context windows.
*   **Suggested Models**: `Gemma 4 31B`, `Mistral Large 2`.

### **Tier 1: Deep Reasoning & PoC Generation**
*   **Role**: Multi-step exploitability analysis and functional exploit generation.
*   **Requirements**: Frontier reasoning capabilities and "Whole-Repo" context.
*   **Suggested Models**: `Qwen 3.5 397B`, `Gemini 3 Flash`.

---

## 🔍 Showcase: From Hit to Validated Exploit

When the `vlnr` agent identifies a high-confidence finding, it produces a detailed triage report and a validated exploit script.

**Example Finding: Server-Side Request Forgery (SSRF)**
*   **Signal**: User-controlled URL from a Web API flows into a low-level socket request.
*   **Agent Decision**: Triage score `0.94`. "Sink reachable via unvalidated user input."
*   **Validation**: The agent generates an exploit script targeting an internal metadata service and confirms the vulnerability by observing a successful exfiltration in the sandbox.

---

## 💻 Getting Started

### Installation
```bash
uv sync
```

### Discovery & Audit Pipeline
Identify high-value targets and perform an automated scan:
```bash
# Discover high-value candidates using semantic scoring
uv run poc-find-candidates --packages "requests,flask" --llm-discovery

# Execute deep scan and triage findings
uv run poc-scan-vulnerabilities top_candidates.json --llm-triage --llm-poc
```

### Autonomous Agent Mode
Launch the fully autonomous agent to explore, scan, and validate vulnerabilities independently:
```bash
uv run vlnr agent --package "target-lib" --budget 10.0
```

---

## ⚙️ Configuration
Configure model routing and API endpoints in `llm_config.yaml`.
- `LLM_API_KEY`: Your preferred LLM provider key.
- `GITHUB_TOKEN`: (Optional) For high-rate repo metadata fetching.

---

## 🧪 Quality & Standards
Built for security-critical environments with a focus on reliability and correctness:
- **Strict Typing**: Full MyPy coverage with `--strict`.
- **Reproducible Tests**: Logic verified via `pytest` with extensive mocking for external dependencies.
- **Modern Tooling**: Built on the `uv` Python toolchain.

---
*Created by [nandrzej](https://github.com/nandrzej)*
