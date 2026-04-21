
# VLNR Methodology Upgrade - Implementation Plan

This plan outlines the systematic upgrade of the VLNR vulnerability discovery methodology, addressing scoring accuracy, scanning depth, LLM triage reliability, and operational safety.

## 1. Core Principles

- **Dual-Mode Scoring:** Discovery (finding new bugs) vs. Triage (prioritizing known CVEs).
- **Signal-Rich Prioritization:** Use centrality (dependency graph), recency, and audit history.
- **Deep Scanning:** Target modern supply-chain patterns (`__init__.py`, `METADATA`, `tests/`).
- **Container-First Safety:** Isolate all PoC validation in containers (OrbStack).
- **Standards-Driven Output:** Produce OpenVEX for integration with vulnerability management tools.
- **TDD with VCR:** Write tests before implementation for all new features. Use `vcrpy` to record and replay HTTP interactions, especially for LLM calls.
- **LLM Verification:** Initially verify all LLM integrations against a local endpoint (`http://127.0.0.1:1234/v1`) using the `qwen3.5-2b-mlx` model for all tiers.
- **Provider Abstraction:** Never hardcode LLM provider or model names in source code. Use a centralized `llm_config.yaml` for model routing and parameters.

***

## 2. Implementation Phases

### Phase 1: Foundation & Critical Fixes (Data Model & Bug Fixes)

*Goal: Address immediate bugs and establish the data structures required for subsequent phases.*

- **Target Files:**
  - `vlnr/models.py`:
    - Update `VulnerabilityRecord`:
      - Add `cvss_score: float | None`
      - Add `epss_score: float | None`
      - Add `vex_status: VexStatus | None` — typed as a `Literal["affected", "not_affected", "fixed", "under_investigation"]`, not a free-form string, to ensure OpenVEX-conformant output in Phase 5.
    - Add `audit_interest_score` field to `CandidateRecord`.
  - `vlnr/vuln_ast.py`: **Fix bug** — Remove `yaml.safe_load` from `SINKS`. Only `yaml.load` without `SafeLoader` is a vulnerable sink.
  - `vlnr/vuln_heuristics.py`:
    - Define `rules/` directory with pinned rule versions.
    - Enable OpenGrep rule categories: `injection`, `ssrf`, `deserialization`, `path-traversal`. Specifically enable SSRF rules covering `urllib`, `httpx`, and `aiohttp` calls with user-controlled URLs.

***

### Phase 2: Signal Intelligence (Scoring & Metadata)

*Goal: Implement refined scoring formulas, restore dependency centrality, and implement metadata injection scanning.*

- **Pre-requisite (TDD):** Create `tests/test_scorer.py` and `tests/test_metadata_scan.py`.
- **Target Files:**
  - `vlnr/scorer.py`:
    - Implement **Discovery mode**: `Score = centrality × w1 + Popularity × w2 + recency × w3`
    - Implement **Triage mode**: `Score = 0.5 × EPSS + 0.2 × clamp(CVSS) + 0.3 × Popularity`
    - **Centrality:** Build the reverse-dependency graph from `requires_dist` in the JSONL stream (O(n), no API calls). This restores the only unique signal the original scorer had — packages like `certifi` and `urllib3` have enormous blast radius that popularity alone does not capture.
    - **Audit Interest:** Rename `compute_audit_score` → `compute_audit_interest_score`. Invert the direction: a CVE history signals a vulnerable codebase worth deeper audit. Use a bounded, non-monotonic function: packages with 1–10 CVEs score highest (demonstrated vulnerability, likely more unpatched), packages with 0 CVEs score neutral (unaudited, unknown), packages with 50+ CVEs score slightly lower (well-studied, low residual yield).
    - **Recency:** Add 10–15% weight to `pop_score` for 30-day upload recency. A recently-updated high-popularity package is the xz-utils attack pattern.
    - **Unknown stars:** Treat `repo_stars = None` (unknown host) as absent from the `pop_score` component, not as `0`. Substituting `0` penalizes non-GitHub repos; substituting a neutral value inflates scores uncontrollably. Exclude the component when data is unavailable.
  - `vlnr/osv.py`:
    - Load EPSS scores from `https://epss.cyentia.com/epss_scores-current.csv.gz`. Use a simple date-based TTL: check if a local cached file exists and was written today (compare file mtime date to `date.today()`). If yes, use the cache. If no, download and overwrite. No expiry logic beyond this.
    - Stop filtering by `ecosystem == "PyPI"` for the advisory cross-reference pass. Advisories from other ecosystems (NuGet, Cargo, npm, Maven) attach to PyPI candidates as signals only — not as automated escalations — because cross-ecosystem version matching is unreliable. Flag these hits for manual or LLM-assisted review.
  - `vlnr/github.py`:
    - Add GitLab star support via the GitLab API.
    - Return `None` (not `0`) for repositories on unsupported hosts.
  - `vlnr/vuln_metadata.py` *(new file)*:
    - Implement wheel `METADATA` parsing from `.dist-info/METADATA`. This is an RFC 822-style text file, not Python source — it must not go in `vuln_ast.py`.
    - Scan `Description`, `Summary`, and `Home-page` fields for injected shell commands, suspicious URLs, and encoded payloads.
    - Called from `vlnr/vuln_cli.py` at the same pipeline stage as `discover_entrypoints`.

***

### Phase 3: The Bypass Track (Advanced Scanning)

*Goal: Expand detection of supply-chain attacks that skip the standard Evidence Ladder.*

- **Pre-requisite (TDD):** Create `tests/test_bypass_scan.py`.
- **Target Files:**
  - `vlnr/vuln_ast.py`:
    - Add scanning for top-level execution in `__init__.py` — detect `os.system`, `subprocess`, `urllib`, and `requests` calls that appear outside of any function or class body.
    - Explicitly include `tests/`, `conftest.py`, and fixture directories in the bypass scan scope. Malicious packages frequently embed payloads in test files because developers assume test code is low-scrutiny.
  - `vlnr/vuln_cli.py`:
    - **Conjunctive Bypass:** Require ≥2 co-occurring signals before escalating to `PoC_Exploitable`. Examples of qualifying pairs: `base64 + exec/eval`, `network call + dynamic import`, `os.system + obfuscated string`. A single signal produces `Heuristic_Signal` and proceeds through Stage 1 triage like all other findings. This applies equally to `setup.py`, `__init__.py`, and `METADATA` hits.

***

### Phase 4: Triage & LLM Pipeline (liteLLM & Validation)

*Goal: Rebuild the triage pipeline with provider abstraction and establish a ground-truth accuracy baseline.*

- **Pre-requisite (TDD):** Create `tests/test_llm.py` and `tests/test_triage.py` using `vcrpy`.
- **Target Files:**
  - `vlnr/llm.py`: Integrate `liteLLM` as the unified LLM call interface. Replace all direct API calls.
  - `vlnr/triage.py`: Implement Stage 1 (Tier A) batching with plausibility threshold > 0.6. Keep batch sizes ≤5 findings per call to mitigate attention anchoring on the most prominent finding.
  - `vlnr/vuln_reasoner.py`: Implement Stage 2 (Tier B) PoC generation with CWE hints in prompts. Populate `suggested_cwe` in `TriageResult`.
  - `llm_config.yaml` *(new file)*: Centralize all model slugs, provider settings, temperature, and `reasoning_effort` parameters. Configure initial verification target: `base_url: http://127.0.0.1:1234/v1`, `model: qwen3.5-2b-mlx` for all tiers. No model names hardcoded anywhere in source.
  - **Ground-truth requirement:** Before deploying the 0.6 threshold, construct a labeled dataset of 50–100 slices from published CVE PoCs and known-benign packages. Measure precision and recall at thresholds 0.4, 0.5, 0.6, 0.7, 0.8. The measured threshold — not 0.6 assumed — becomes the acceptance criterion. Validate batching accuracy against single-slice triage on the same dataset.

***

### Phase 5: Safety & Output (Validation & VEX)

*Goal: Secure PoC validation and standards-compliant reporting.*

- **Target Files:**
  - `vlnr/vuln_validate.py`:
    - **Container Isolation:** Use OrbStack to run all PoC validation. No host venv execution under any circumstances. The pipeline must fail explicitly — not silently degrade to venv — if the container runtime is unavailable. This is not optional: the tool's bypass track is explicitly designed to handle packages that run arbitrary code at install time; running their PoCs in a bare venv on the host is a direct host compromise risk.
    - **`Runtime_Reachable`** rung: Define as "PoC validated with expected exception or expected output by `vuln_validate.py`." Wire this into the pipeline as the gate between `Static_Path_Confirmed` (CodeQL output) and `PoC_Exploitable` (confirmed PoC).
  - `vlnr/vuln_cli.py` / `vlnr/models.py`:
    - When `is_false_positive=True` is set by LLM triage, emit a minimal OpenVEX JSON document alongside the findings JSON. Use the `vex_status` Literal type defined in Phase 1 to ensure conformant output. This makes findings consumable by downstream tools like OWASP Dependency-Track.

***

## 3. Verification Plan

### Acceptance Criteria

1. **Scoring — centrality:** `certifi` and `urllib3` rank in the top tier due to centrality weight.
2. **Scoring — audit interest:** A package with 5 CVEs scores higher in `audit_interest_score` than a package with 0 CVEs or a package with 60 CVEs.
3. **Scoring — unknown stars:** A GitLab-hosted package does not receive a star penalty vs. an equivalent GitHub-hosted package.
4. **Bypass — conjunctive:** A `setup.py` with a single bare `os.system("make")` call does not escalate to `PoC_Exploitable`. A `setup.py` with `os.system` + a base64-encoded payload does.
5. **Bypass — `__init__.py`:** Known malicious packages using `__init__.py` top-level payloads are flagged.
6. **Bypass — `tests/`:** A payload embedded in `conftest.py` is detected by the bypass scan.
7. **Safety:** The pipeline raises an explicit error if OrbStack is unavailable at PoC validation time. The test must confirm no fallback to venv occurs.
8. **Accuracy:** LLM triage achieves >80% recall on the labeled ground-truth dataset. Threshold selected from empirical measurement, not assumed.
9. **VEX:** A finding marked `is_false_positive=True` produces a valid OpenVEX JSON document with a conformant `vex_status` value.
10. **Quality:** `ruff check` and `mypy --strict` pass on all modified files after each phase.

***

## 4. Risks & Mitigations

| Risk | Mitigation |
| :--- | :--- |
| **OSV cross-ecosystem version matching unreliable** | Treat non-PyPI advisory hits as signals only. Flag for manual or LLM-assisted review, never auto-escalate. |
| **LLM batching attention anchoring** | Cap batch size at ≤5 findings. Validate accuracy against single-slice baseline on ground-truth dataset in Phase 4. |
| **EPSS CSV staleness** | Simple date-based TTL: re-download if local cache mtime date ≠ today. No complex expiry logic. |
| **Container startup overhead** | Use pre-warmed OrbStack base images to minimize PoC validation latency. |
| **`audit_interest_score` non-monotonic edge cases** | Add explicit test criterion (acceptance criterion 2 above) covering 0, 5, and 60 CVE cases before the formula is finalised. |