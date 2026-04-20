# Minimal Tool Specification: Static Vulnerability Finder for Candidate PyPI Projects

## 0. Purpose and Scope

- Input: List of candidate Python packages from previous tool (name, version, repo URL, category, score).
- Output: For each package, a list of **high-confidence static findings** + **LLM-ready slices** for manual or later automated triage.
- Constraints:
  - Laptop / low-resource VM.
  - Purely static; no execution, sandboxing, or network I/O to run code.
  - Focus on: CLI / dev / ML / AI tooling, especially **command injection**, **path traversal / unsafe FS**, **unsafe (de)serialization**, **dynamic code eval**, **obvious network/crypto misuses**.[web:171][web:176][web:178]

---

## 1. Inputs

- `candidates.json` (from previous tool):
  - Array of `{ name, version, repo_url, category_tags, candidate_score, ... }`.
- Environment:
  - Local filesystem with git, Python 3.x.
  - Optional: Semgrep, Bandit, Ruff installed.[web:183][web:176][web:177]
- Optional configuration file `config.yaml`:
  - `max_packages`, `max_files_per_pkg`, `max_sinks_per_pkg`.
  - Inclusion/exclusion patterns for files/directories.

---

## 2. External Dependencies

- **VCS**:
  - `git` for cloning repos.
- **Static tools (optional but recommended)**:
  - `bandit` for baseline security checks; known rules for subprocess, eval, deserialization etc.[web:183][web:175]
  - `ruff` for Bandit-derived security rules (e.g., S602/S604 for subprocess shell).[web:177][web:180]
  - `semgrep` with Python security rulesets, especially `dangerous-subprocess-use` and command injection rules.[web:176][web:178][web:181]

---

## 3. High-level Pipeline

For each candidate package:

1. `fetch_source`
2. `discover_entrypoints`
3. `pre_scan_heuristics` (Bandit/Ruff/Semgrep)
4. `ast_taint_scan` (custom, intra-project but shallow)
5. `slice_construction`
6. `classification_and_scoring`
7. Emit:
   - `findings.json` per package.
   - Optional: `slices.jsonl` per package (LLM-ready).

Each stage must be **streaming / incremental**, with per-package cleanup to conserve disk and RAM.

---

## 4. Stage 1 – Fetch Source

### 4.1 Clone / checkout

- For each candidate:
  - Clone `repo_url` (shallow clone: `--depth=1`).
  - Checkout tag/commit corresponding to selected PyPI `version` if possible:
    - Use git tags that match `v<version>` or `<version>`.
    - Fallback: default branch head if tag not found.

### 4.2 Repository filtering

- Skip package if:
  - Repository missing / clone fails.
  - No `.py` files found under included directories (excluding `tests/` by default, configurable).

---

## 5. Stage 2 – Discover Entry Points and Context

### 5.1 CLI / API entrypoints

- Parse:
  - `setup.cfg`, `pyproject.toml`, or `setup.py` (static string search) for:
    - `console_scripts` in `entry_points`.
    - `scripts` entries.
- For each console script:
  - Resolve `module:function` or module path to actual file and function.
- Identify likely **public APIs**:
  - Top-level functions/classes in `__init__.py` and root modules under package directory.

### 5.2 Classified context

- For each package, maintain:
  - `entrypoints_cli` = list of `module, function, file, line`.
  - `entrypoints_api` = list of exported functions.
  - `framework_hints` inferred from imports: `click`, `argparse`, `typer`, ML libs, etc.

---

## 6. Stage 3 – Pre-scan Heuristics (Reusable Tools)

### 6.1 Bandit / Ruff pass (optional but cheap)

- Run Bandit:
  - `bandit -r . -f json -q` (or equivalent API) limited to:
    - Only security checks relevant to: subprocess, eval/exec, deserialization, filesystem, SSL.[web:183][web:175]
- Run Ruff:
  - Enable security rules S60x (e.g., `subprocess-popen-with-shell-equals-true`, `call-with-shell-equals-true`).[web:177][web:180]
- Normalise findings into a unified format:
  - `{ file, line, rule_id, message, severity, cwe?, raw_tool }`.

### 6.2 Semgrep pass

- Run Semgrep with Python security rules:
  - Core rulesets: dangerous subprocess use, command injection, unsafe yaml load, eval/exec patterns.[web:176][web:178][web:181][web:184]
- Collect:
  - `{ file, start_line, end_line, rule_id, message, severity, cwe?, dataflow_trace? }`.

### 6.3 Heuristic consolidation

- Merge Bandit/Ruff/Semgrep alerts into **candidate sink list**:
  - Deduplicate by `(file, line-range, sink-kind)`.
  - Maintain mapping:
    - `sink_id -> underlying tool hits`.

- This stage is **fast triage**, not final classification; all these alerts are suspect, not confirmed.

---

## 7. Stage 4 – Custom AST-based Taint Scan

Goal: focus on a small set of **80/20 vulnerability patterns**, mainly command injection and path/file abuse, which the large-scale PyPI study shows are highly prevalent and dominated by `subprocess` misuse.[web:171]

### 7.1 Source identification

- Per file, using Python `ast`:
  - Mark as **taint sources**:
    - `sys.argv[*]`
    - `os.environ[...]`
    - `input()`
    - CLI frameworks:
      - `click` argument/option values, `argparse` parsed arguments (`args.*`).
    - File/config values loaded from obvious user-controlled places (heuristic, e.g., YAML or JSON file path derived from CLI argument).

### 7.2 Sink identification

- **Process execution sinks**:
  - `subprocess.Popen/run/call/check_output`, `os.system`, `os.popen`, `pexpect.spawn`, etc.
  - For each call:
    - Record `shell` argument (constant True/False).
    - Record positional and keyword args.

- **Filesystem sinks**:
  - `open`, `os.open`, `os.remove`, `os.rename`, `shutil.*`, `Path().write_*`, `Path().unlink`, etc.
  - `glob.glob`, dangerous recursion into user-provided directories.

- **Deserialization sinks**:
  - `pickle.load/loads`, `dill.load/loads`, `joblib.load`, `yaml.load` (without safe loader).

- **Dynamic code execution sinks**:
  - `eval`, `exec`, `compile`, `execfile`, runtime `import_module` with user data.

- **Network sinks (only simple patterns)**:
  - `requests.get/post/...` with `verify=False`, or building URLs from tainted data.

### 7.3 Simple intra-module taint analysis

- For each module:
  - Build a **dataflow graph** per function:
    - Assignments `x = expr`, attribute and subscript assignments, returns.
    - Track variable definitions and uses.

- For each sink call:
  1. Identify the AST nodes for each argument.
  2. Backwards-walk within:
     - Same function first.
     - If value from parameter, escalate to caller summary (shallow inter-procedural; call-graph limited to same module or known entrypoints).
  3. Mark a value as **tainted** if:
     - It derives directly from a source.
     - Or from another tainted variable via assignments, formatted strings, function arguments (limited depth).
  4. Recognise **sanitizers** (simple whitelist):
     - `shlex.quote`, `urllib.parse.quote`, restrictive validation functions (regex that only allow safe chars).

- Result: For each sink, record:
  - `tainted_args` (which argument positions/keywords are tainted).
  - `sanitizer_chain` (if any).
  - `source_path` (sequence of variables/functions from entrypoint to sink, best-effort).

### 7.4 Rule-based classification (static only)

Assign a **static classification** per sink:

- `static_class = { "obvious_vuln" | "suspicious" | "benign" }`

Examples:

- `obvious_vuln`:
  - `subprocess.*(cmd, shell=True)` and `cmd` tainted, with no sanitizers in chain.
  - `os.system(cmd)` where `cmd` tainted.
  - `pickle.load(open(path))` where `path` tainted from CLI.
  - `yaml.load(data)` (unsafe loader) where `data` from remote input.

- `suspicious`:
  - `shell=False` but command list contains tainted arguments (possible injection into flags/paths).
  - File operations on paths derived from tainted input with no normalized checks.
  - `eval(expr)` where `expr` tainted.

- `benign`:
  - Sinks with no tainted arguments.
  - Sinks with clear sanitization (e.g., `shlex.quote` before `shell=True`).

---

## 8. Stage 5 – Slice Construction (LLM-Ready Evidence)

For every sink with `static_class != benign`:

- Construct a **slice** capturing only the essential context:

### 8.1 Slice structure

- `slice_id` (unique).
- `package_name`, `version`.
- `sink`:
  - `file`, `line`, `function`, `api` (e.g., `subprocess.run`).
- `entrypoint_context`:
  - CLI/API function and signature, file, line.
- `code_snippets`:
  - For all relevant functions on the tainted path:
    - Extract ±K lines around function definitions and sink call.
- `dataflow_summary`:
  - Ordered list of nodes: `source -> ... -> sink`.
  - For each node: `file`, `line`, `expr` (pretty-printed).
- `taint_info`:
  - `tainted_args`, `source_types` (argv/env/input/etc.).
  - `sanitizers` used (if any).
- `tool_support`:
  - Associated Bandit/Ruff/Semgrep findings for this location (rule IDs, messages, severities).[web:183][web:176][web:181]

### 8.2 Size constraints

- Limit:
  - Max functions per slice (e.g., <= 5).
  - Max total code lines per slice (e.g., <= 300).
  - If larger, prune to:
    - Entry function(s), one mid-path helper, sink function.

This keeps LLM prompts small and avoids long-context issues.

---

## 9. Stage 6 – Classification and Scoring

### 9.1 Local scoring

For each slice:

- Compute `risk_score_static` based on:
  - Static classification (`obvious_vuln` > `suspicious`).
  - Sink type (command injection > deserialization > path).
  - Number of tainted arguments.
  - Presence/absence of sanitizers.
  - Supporting tool hits (multiple tools agreeing → higher score).[web:171][web:175][web:177][web:181]

Example (0–1 scale):

- Start with base by sink category.
- Add 0.2 if multiple tools flagged the same site.
- Subtract 0.2 if any sanitizer detected.

### 9.2 LLM interface contract (optional, but defined)

Define a **JSON schema** for downstream LLM triage:

```json
{
  "slice_id": "pkg@1.2.3:subprocess.py:42",
  "package": "pkg",
  "version": "1.2.3",
  "category": ["cli", "ml"],
  "sink_api": "subprocess.run",
  "static_class": "obvious_vuln",
  "risk_score_static": 0.92,
  "cwe_candidates": ["CWE-78"],
  "source_types": ["argv"],
  "tainted_args": ["args"],
  "sanitizers": [],
  "entrypoint": {
    "file": "pkg/cli.py",
    "function": "main",
    "line": 10
  },
  "code_snippets": [
    {
      "file": "pkg/cli.py",
      "start_line": 1,
      "end_line": 80,
      "code": "..."
    },
    {
      "file": "pkg/shell.py",
      "start_line": 1,
      "end_line": 120,
      "code": "..."
    }
  ],
  "dataflow_summary": [
    {"file": "pkg/cli.py", "line": 20, "expr": "cmd = args.command"},
    {"file": "pkg/shell.py", "line": 45, "expr": "subprocess.run(cmd, shell=True)"}
  ],
  "tool_hits": [
    {"tool": "bandit", "rule": "B602", "severity": "HIGH"},
    {"tool": "ruff", "rule": "S602", "severity": "HIGH"},
    {"tool": "semgrep", "rule": "dangerous-subprocess-use", "severity": "ERROR"}
  ]
}
```

The tool **does not** have to invoke the LLM; it only needs to generate this schema.

---

## 10. Outputs

### 10.1 Per-package findings

`<pkg_name>-findings.json`:

- `package` metadata.
- `sinks`:
  - List of slice summaries: `slice_id`, `sink_api`, `static_class`, `risk_score_static`, `file`, `line`, brief description.
- `stats`:
  - `num_sinks_total`
  - `num_obvious_vuln`
  - `num_suspicious`
  - `num_benign`
  - `num_files_scanned`, `num_bandit_hits`, etc.

### 10.2 Global index

`all-findings-index.json`:

- Flattened list of all slices (lightweight):
  - `slice_id`, `package`, `risk_score_static`, path to slice record in per-package file.

---

## 11. CLI Interface (Minimal)

- Command:  
  `poc-find-vulns --candidates candidates.json --out out_dir [options]`

- Options:
  - `--max-packages N`
  - `--max-files-per-pkg M`
  - `--max-sinks-per-pkg K`
  - `--use-bandit/--no-bandit`
  - `--use-ruff/--no-ruff`
  - `--use-semgrep/--no-semgrep`
  - `--include-tests` (default false)
  - `--config config.yaml`

- Behavior:
  1. Load candidates.
  2. For each (respecting `max-packages`):
     - Clone repo.
     - Run stages 2–6.
     - Save per-package findings and slices.
     - Clean checkout directory (optional cache) to free resources.
  3. Emit global index.

---
