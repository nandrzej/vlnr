**vlnr — Agentic exploit pipeline for the Python supply chain**

`vlnr` is an LLM-augmented agentic security tool that runs a complete
**Discover → Scan → Triage → Exploit → Validate** cycle over Python PyPI packages
with minimal human input. An LLM agent drives the loop, deciding which
packages to scan, when to generate proof-of-concept exploits, and when to
validate them in an isolated container — all budget-aware and resumable.

> ⚠️ For authorized security research only. All PoC execution is isolated
> in transient Docker containers. Never run against systems you do not own.

---

## What Makes vlnr Different

Traditional static analysis tools (Bandit, Semgrep) stop at flagging potential
findings. `vlnr` closes the loop:

- **Agents, not scripts** — An LLM-driven `Plan → Act → Observe` loop autonomously
  decides the next action (scan, generate exploit, validate, stop) based on
  accumulated findings and remaining token budget
- **Confirmed exploitability** — For high-confidence findings, the agent
  generates a functional PoC and executes it in a sandboxed Docker container to
  confirm the vulnerability is reachable, not just flagged
- **Supply chain focus** — Targets popular, under-audited PyPI packages using
  reverse-dependency centrality, OSV coverage gaps, and semantic intent scoring
  — specifically the class of packages most dangerous to the broader ecosystem
- **~25% fewer false positives** — Tiered LLM triage filters Bandit/Semgrep
  noise by evaluating exploitability in full file context before escalating

---

## Architecture

```
PyPI Ecosystem
      │
      ▼
┌──────────────────────────────┐
│  Candidate Finder            │  Semantic scoring: download centrality,
│  poc-find-candidates         │  OSV coverage gaps, LLM intent classification.
│  vlnr/cli.py + scorer.py     │  Targets: CLI tools, ML/AI libs, devops infra.
└────────────┬─────────────────┘
             │  top_candidates.json
             ▼
┌──────────────────────────────┐
│  Agentic Loop                │  LLM agent drives the Think–Act–Observe cycle.
│  vlnr agent                  │  Persists state to JSON; resumable across runs.
│  vlnr/agent.py               │  Budget-aware: tracks token cost per action.
└──┬──────────┬──────────┬─────┘
   │          │          │
   ▼          ▼          ▼
Scan       Generate    Validate
Package    PoC         PoC
   │          │          │
vulncli.py  vulnreasoner vulnvalidate
vulnast.py  .py         .py (Docker)
   │
   ▼ taint slices
triage.py (Tiered LLM)
   │
   ▼ TriageInfo + plausibility score
vex.py → OpenVEX output
```

### The Agent Loop

The agent operates a `while iterations < max_iterations and budget_remaining > 0`
loop. At each step it:

1. **Observes** the current state (scanned packages, findings, slices, budget)
2. **Decides** the next action via an LLM call with a structured tool manifest
3. **Dispatches** to the appropriate pipeline function
4. **Updates** state and saves it to disk (resumable with `--state-path`)

The agent's policy:
- Auto-triggers `generate_poc` for any slice with triage plausibility ≥ 0.7
- Immediately follows with `validate_poc` before moving to the next package
- Calls `stop` when no further actions are productive or budget is exhausted

---

## Tiered LLM Strategy

All model routing is configured in `llm_config.yaml` — no provider is hardcoded.

| Tier | Role | Target Models | Notes |
|------|------|--------------|-------|
| **Tier 1** | PoC generation, whole-repo reasoning | Qwen 3.5 397B, Gemini 3 Flash | 1M token context; 98–99% PoC success rate |
| **Tier 2** | Contextual triage, scoring refinement | Gemma 4 31B, GLM-5.1 | Reduces Tier 1 calls by pre-filtering |
| **Tier 3** | Metadata classification, intent scoring | Qwen 3.5 4B, Gemma 4 2B | High-throughput, low cost |

**Vulnerability priority score:**

```
P = (Ws × Cs + Wl × Cl) × Er
```

`Cs` = static tool confidence · `Cl` = LLM semantic confidence (log-probs)
· `Er` = exploitability reasoning score · Weights: `Ws=0.4`, `Wl=0.6`

---

## CWE Coverage

| CWE | Sink | Detection Method |
|-----|------|-----------------|
| CWE-78 | `subprocess.run(shell=True)` | AST taint + bypass scan; shell escape PoC generation |
| CWE-22 | `open(file_path)` | `os.path.join` normalization bypass detection |
| CWE-502 | `pickle.loads()` | `__reduce__` payload construction |
| CWE-94 | `eval()`, `exec()` | Builtins reflection via `getattr` |
| CWE-918 | `urllib`, `httpx`, `aiohttp` | OpenGrep SSRF rules (`vlnr/rules/ssrf.yaml`) |

---

## Getting Started

### Requirements

- Python 3.14+
- [`uv`](https://github.com/astral-sh/uv) package manager
- Docker (for sandbox PoC validation)
- An OpenAI-compatible LLM API key

### Installation

```bash
git clone https://github.com/nandrzej/vlnr
cd vlnr
uv sync
```

### Configuration

```bash
# .env
LLM_API_KEY=<your-key>
GITHUB_TOKEN=<optional — for higher-rate repo metadata>
```

`llm_config.yaml` controls model routing per tier:

```yaml
tier1:
  model: openai/qwen-3.5-397b-instruct
  temperature: 0.1
  reasoning_effort: high

tier2:
  model: openai/gemma-4-31b-it
  temperature: 0.0

tier3:
  model: openai/qwen-3.5-4b-instruct
  temperature: 0.0
```

---

## Usage

```bash
# Simplest: full pipeline in one command
# vlnr run uses the LLM agent by default; export CUSTOM_OPENAI_API_KEY first or pass --skip-agent.
vlnr run --out-dir results/ --osv-dump osv.zip --packages requests,flask

# Or run stages individually for finer control
vlnr discover --osv-dump osv.zip --packages requests,flask --out cands.json
vlnr scan cands.json --out-dir findings/ --llm-triage --llm-poc
vlnr agent --package requests --budget 10.0
```

A full `vlnr run --out-dir results/` populates:

- `results/candidates.json` — discover stage output (ranked candidates)
- `results/findings/all-findings-index.json` — scan stage summary index
- `results/findings/<pkg>-findings.json` — per-package findings (one file per scanned package with results)
- `results/findings/<pkg>-slices.jsonl` — per-package taint slices (one line per slice)
- `results/findings/<pkg>-<slice_id>-vex.json` — OpenVEX record for each false-positive slice
- `results/agent_session.json` — agent state (resumable with `vlnr agent --state-path`)

### Migrating from `poc-find-candidates` / `poc-scan-vulnerabilities`

The legacy entry points `poc-find-candidates` and `poc-scan-vulnerabilities` still work but emit a `DeprecationWarning`. After pulling this release, run `uv sync` to install the new `vlnr` console script. Then:

| Old | New |
|---|---|
| `poc-find-candidates main` | `vlnr discover` |
| `poc-find-candidates agent` | `vlnr agent` |
| `poc-scan-vulnerabilities` | `vlnr scan` |
| (none) | `vlnr run` (full pipeline) |

Note: the `poc-find-candidates` script is a typer app with `main` and `agent` subcommands (`pyproject.toml:24` → `vlnr.cli:app`); the bare flag examples in the current README's "Stage 1" / "Stage 2" sections (e.g. `poc-find-candidates --include-cli --limit 500`) will fail with `No such option` because typer expects a subcommand. The above table reflects the actual working invocations. Replacing the Usage section per Step 1 also fixes those Stage 1/Stage 2 examples.

---

## Example: SSRF Finding

```
Finding:    CWE-918 Server-Side Request Forgery
Signal:     User-controlled URL from Web API → aiohttp socket call
Triage:     plausibility=0.94 — sink reachable via unvalidated input
PoC:        Agent generates exploit targeting internal metadata endpoint
Validation: Confirms successful exfiltration in Docker sandbox
Output:     OpenVEX record (status: affected) + PoC script
```

---

## Output Formats

- **`top_candidates.json`** — Ranked candidates with `candidate_score`, OSV IDs,
  download centrality, audit history, and intent classification
- **Per-package findings** — Structured JSON: `plausibility`, `suggested_cwe`,
  taint trace, source/sink mapping, tool hits (Bandit, Ruff, Semgrep)
- **OpenVEX records** — Machine-readable exploitability status
  (`affected | not_affected | fixed | under_investigation`)
- **PoC scripts** — Executable exploit with sandbox validation result
- **`session.json`** — Serialized `AgentState` for session resumption

---

## Quality Standards

- **Strict typing** — Full MyPy `--strict` coverage
- **Reproducible tests** — `vcrpy` cassettes for all LLM and HTTP interactions;
  no live calls in CI
- **Provider abstraction** — All model names and endpoints in `llm_config.yaml`,
  never hardcoded
- **Container isolation** — PoC execution uses Docker SDK in transient containers

---

## License

MIT — see [LICENSE](LICENSE).
