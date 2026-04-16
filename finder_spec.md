# Minimal Tool Specification: Candidate Python Project Finder (PyPI)

## 0. Purpose and Scope

- Goal: Identify **high‑value Python packages** on PyPI (CLI, dev, ML/AI tools) that are:
  - Widely used / central in dependency graphs.
  - Not known to be vulnerable (or only lightly covered) in **OSV / PyPI advisory / GHSA**.
  - Likely under‑audited, thus good candidates for deeper static + LLM analysis.
- Output: Ranked list of package candidates with metadata and scores.
- Constraints:
  - Must run on a laptop / low‑resource VM.
  - Static data only (PyPI, OSV, advisory DB, GitHub metadata).
  - No code scanning yet; this spec covers **candidate selection only**.

---

## 1. Inputs and Data Sources

### 1.1 Package universe

- Source A: **PyPI package index** (project names and metadata):
  - Use either:
    - Bulk dataset: `pypi-json-data` (PyPI JSON snapshots in SQLite/JSON).[web:164]
    - Or `simple` / `JSON API` endpoints: `https://pypi.org/pypi/<name>/json`.[web:152][web:161]
- Required fields per project (from `info` / metadata):[web:152][web:158]
  - `name`
  - `version` (latest)
  - `summary`
  - `classifiers`
  - `project_urls` (incl. `Code`, `Homepage`, `Source`, etc.)
  - `vulnerabilities` (PyPI’s own listing; may be empty).[web:152]
  - `downloads` (if available from external datasets; PyPI’s legacy field is useless).[web:152]
  - `requires_dist` / dependency info if present.

### 1.2 Vulnerability information

- Source B: **OSV.dev PyPI ecosystem**:
  - Use GCS dumps: `gs://osv-vulnerabilities/PyPI/`, or OSV HTTP API.[web:143][web:154]
  - For each vulnerability record:
    - `id` (e.g., `PYSEC-2024-24`).[web:162][web:159]
    - `affected` packages (name, version ranges).
    - `ecosystem_specific` details (e.g., vulnerable functions) when present.[web:159]
- Source C: **PyPA advisory database**:
  - GitHub repo: `pypa/advisory-database`.[web:159]
  - YAML advisories with:
    - `id` (PYSEC).
    - `package` name, version ranges.
    - Links to CVEs, URLs, GHSA IDs.
- Source D (optional): **GitHub Advisory Database (GHSA)**:
  - Bulk via OSV’s “GitHub” ecosystem or GitHub API.[web:153][web:143]

### 1.3 Popularity and centrality

- Source E: **Download / popularity / dependency data**:
  - Download counts from:
    - Public datasets (e.g., `pypi-stat` style or other research datasets).[web:145][web:150]
  - Dependency graph / reverse-dependency info from:
    - Public research datasets mapping dep graphs (e.g., vulnerability‑dependency datasets, OSPtrack / FGI studies).[web:145][web:150][web:147]
  - If not available, approximate popularity via:
    - GitHub stars and forks (from repo URL).
    - Number of dependents from services (if API limits allow).

---

## 2. Package Filtering Pipeline

### 2.1 Category filter (CLI / dev / ML / AI)

For each package:

- Accept if **any** of:

  1. **Classifiers** (from `classifiers`):[web:152][web:158]
     - Contains any of:
       - `Environment :: Console`
       - `Environment :: Console :: Curses`
       - `Topic :: Software Development :: Build Tools`
       - `Topic :: Software Development :: Libraries :: Application Frameworks`
       - `Topic :: Scientific/Engineering :: Artificial Intelligence`
       - `Topic :: Scientific/Engineering :: Information Analysis`
       - `Topic :: System :: Archiving`, `System :: Systems Administration`
       - Other CLI/Dev/AI‑indicative classifiers (configurable list).

  2. **Entry points / scripts**:
     - In `requires_dist` / `project_urls` / distribution metadata, detect:
       - `entry_points.console_scripts` or `scripts` in associated metadata, via:
         - Auxiliary parsing from distribution metadata when available.
     - Heuristic: packages with console scripts are CLI tools.

  3. **Name / summary heuristics**:
     - `name` / `summary` matches regexes:
       - `cli`, `tool`, `manager`, `runner`, `deploy`, `backup`, `monitor`, `lint`, `formatter`, `devops`, `ml`, `ai`, `model`, `training`, `dataset`, `pipeline`, etc.

- Drop packages that:
  - Are clearly libraries only (e.g., purely `django-foo` models) and not tools, unless classification and other signals suggest heavy CLI usage.

### 2.2 Repository accessibility filter

For candidate packages:

- Extract candidate **source repository URL**:
  - Prefer `project_urls['Source']` or `Code`, then `Home Page`.[web:158][web:155]
  - From GitHub, GitLab, etc.

- Filter out packages without:
  - Any accessible repository URL.
  - A reachable public repo (HTTP 200, not 404) if quick HEAD/GET is allowed.

This ensures a follow‑up analysis can actually pull and scan code.

---

## 3. Vulnerability Coverage Filtering

Goal: keep **popular but under‑audited** projects.

### 3.1 Known vulnerability presence

For each package name:

- Compute `known_vuln_count`:
  - Count matching records in OSV PyPI data where `affected.package.name == package`.[web:143][web:162]
  - Plus matching entries in PyPA advisory DB.[web:159]
  - Optionally count GHSA entries where `package` is referenced.

- Compute `latest_version_vulnerable`:
  - From OSV records and PyPI `vulnerabilities` field, check if latest version is in any affected range.[web:152][web:143]

### 3.2 Under‑audited heuristics

Define Booleans:

- `has_any_vuln = known_vuln_count > 0`
- `has_latest_vuln = latest_version_vulnerable == True`

Define “under‑audited” as:

- **Case A: zero known vulns**:
  - `has_any_vuln == False` → likely no prior security focus.
- **Case B: few vulns and large footprint**:
  - `0 < known_vuln_count <= K` (small K, e.g., 1–2) AND
  - package shows strong popularity signals (see scoring below).
  - Rationale: one or two CVEs may indicate **minimal** prior audit, not exhaustive review.

Optionally downrank packages with:

- Many historical advisories and recent security activity (may already be heavily scrutinized).

---

## 4. Popularity and Impact Scoring

For each filtered package, compute a **score** that proxies “impact if vulnerable” and “likelihood of not being heavily audited”.

### 4.1 Signals

Approximate the following (normalised to [0, 1]):

- `pop_downloads`:
  - Normalised log of recent download counts (e.g., from external stats or datasets).[web:145]
- `pop_repo_stars`:
  - Normalised log of GitHub stars (if repo known).
- `centrality_dep`:
  - Normalised reverse-dependency centrality score:
    - Number of direct dependents in dep graph datasets, or approximated through known data.[web:145][web:150][web:147]
- `age_years`:
  - How long since first release; older, still‑popular tools are more likely entrenched.
- `update_recency`:
  - Time since last release:
    - Very old and abandoned + high use = interesting, but more risky in terms of disclosure responsiveness.

### 4.2 Score formulation

Define:

- `vuln_penalty`:
  - 0 if `has_any_vuln == False`
  - Small penalty if `0 < known_vuln_count <= K`
  - Larger penalty if `known_vuln_count > K` (project already widely known for security issues).

- `audit_score = 1 - clamp(vuln_penalty, 0, 1)`

Define candidate ranking score:

- `score = w1 * pop_downloads + w2 * centrality_dep + w3 * pop_repo_stars`
- `candidate_score = score * audit_score`

Tune `w1..w3` to emphasize downloads vs. dependency centrality.

---

## 5. Output Artifacts

### 5.1 Candidate record schema

For each selected candidate, emit a JSON/YAML record:

```json
{
  "name": "package-name",
  "version": "1.2.3",
  "summary": "Short description",
  "classifiers": ["Environment :: Console", "..."],
  "category_tags": ["cli", "ml", "devops"],
  "pypi_url": "https://pypi.org/project/package-name/",
  "repo_url": "https://github.com/org/repo",
  "pop_downloads": 0.87,
  "centrality_dep": 0.65,
  "pop_repo_stars": 0.72,
  "age_years": 4.2,
  "update_recency_days": 180,
  "known_vuln_count": 0,
  "latest_version_vulnerable": false,
  "osv_ids": [],
  "pysec_ids": [],
  "ghsa_ids": [],
  "candidate_score": 0.81
}
```

### 5.2 Ranked list

- Produce:
  - `top_candidates.json` — array of records sorted by `candidate_score` desc.
  - Optionally `top_cli.json`, `top_ml.json`, `top_dev.json` subsets.

---

## 6. Operational Constraints and Performance

- Crawl / data ingestion:
  - Prefer **bulk** datasets (PyPI JSON snapshots, OSV GCS dumps, PyPA advisory repo clone) over live crawling to:
    - Minimise HTTP requests and rate‑limit issues.[web:143][web:159][web:164]
  - Process in streaming batches (e.g., 10k packages at a time) to control memory usage.

- Computation:
  - Simple numeric scoring per package; no static code analysis at this stage.
  - Use local caching for:
    - Repo metadata (GitHub API calls are rate‑limited).  
    - OSV/advisory lookups.

- Extensibility:
  - Category heuristics, weights, and thresholds (e.g., `K` and score cut‑offs) configurable via a small config file.
  - Records can be fed directly into the **next pipeline stage** (static + LLM analysis) without transformation.

---

## 7. Minimal CLI Interface (for this stage)

- Command: `poc-find-candidates [options]`
- Options:
  - `--limit N` – max number of top candidates to output.
  - `--min-downloads X` – filter out very low‑usage projects.
  - `--include-ml`, `--include-cli`, `--include-dev` – category switches.
  - `--osv-dump PATH` – local OSV PyPI data directory.
  - `--pypi-json PATH` – local PyPI JSON dataset / SQLite DB.
  - `--out PATH` – output JSON file.

- Behavior:
  - Load datasets.
  - Filter by category.
  - Join with OSV / advisory data.
  - Compute scores and sort.
  - Emit top N candidate records.
