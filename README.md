# Candidate Python Project Finder (vlnr)

A high-performance pipeline for identifying high-value Python projects for security audits by cross-referencing PyPI metadata with OSV vulnerability data.

## Features

- **Dual Ingestion**: Stream from bulk PyPI JSONL or fetch directly from PyPI JSON API.
- **Vulnerability Matching**: Automatic matching against OSV PyPI vulnerability dumps.
- **Structural Filtering**: Categorizes projects as CLI, ML, or Dev tools using classifiers and heuristics.
- **Heuristic Scoring**: Ranks projects based on a combination of popularity (downloads, stars) and auditability (vulnerability history).

## How It Works

### 1. Data Ingestion
- **Bulk**: Iterates through JSONL records without loading the full set into memory.
- **API**: Async fetching for specific package names with built-in rate limiting.
- **Vulnerability Data**:
  - **OSV Dump**: Processes ZIP-compressed OSV PyPI vulnerability records.
  - **PyPA Advisories**: Optionally merges advisories from a local clone of `pypa/advisory-database` for enhanced coverage.

### 2. Category Filtering
Projects are tagged and filtered into target categories:
- **CLI**: `Environment :: Console` classifiers, `cli`/`tool` keywords, or presence of `console_scripts`.
- **ML**: `Scientific/Engineering :: Artificial Intelligence` classifiers, `ml`/`ai` keywords.
- **Dev**: `Software Development :: Build Tools` classifiers, `devops`/`ci` keywords.

### 3. Scoring Formula
The `candidate_score` [0, 1] is calculated as `popularity_score * audit_score`:
- **Popularity**: Weighted average of log-normalized Downloads (40%), GitHub Stars (20%), and Centrality (40%).
  - **Centrality**: Measures ecosystem importance based on dependent count, provided via `--deps-csv`.
- **Audit**: Penalty-based score starting at 1.0. 
  - 1-2 vulns: 0.8
  - 3+ vulns: 0.5 base penalty with progressive reduction per additional vulnerability.

## Installation

```bash
uv sync
```

## Usage

### Find candidates from bulk dump
```bash
poc-find-candidates --pypi-json path/to/pypi.jsonl --osv-dump path/to/osv-pypi.zip
```

### Find candidates for specific packages
```bash
poc-find-candidates --packages "requests,flask,rich" --osv-dump path/to/osv-pypi.zip
```

### Full Options
- `--pypi-json`: Path to bulk JSONL.
- `--packages`: Comma-separated package list.
- `--osv-dump`: **(Required)** Path to OSV PyPI ZIP dump.
- `--pypa-repo`: Path to local clone of `pypa/advisory-database`.
- `--downloads-csv`: Optional CSV (name,count) for real download data.
- `--deps-csv`: Optional CSV (name,count) for package dependents (centrality).
- `--limit`: Max candidates to output (default 100).
- `--include-cli / --include-ml / --include-dev`: Category toggles.
- `--out`: Output JSON path (default `top_candidates.json`).

## Development

```bash
# Run tests
PYTHONPATH=. uv run pytest

# Linting
uv run ruff check .
uv run mypy --strict vlnr/
```
