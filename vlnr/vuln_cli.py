import json
import logging
import os
import ast
import signal
import uuid
from pathlib import Path
from datetime import datetime
from typing import Any, Optional

from vlnr.llm import LLMClient
from vlnr.triage import triage_vulnerabilities_batch
from vlnr.vuln_reasoner import generate_poc
from vlnr.vuln_fetch import fetch_source, cleanup_source
from vlnr.vuln_entrypoints import discover_entrypoints
from vlnr.vuln_metadata import scan_metadata
from vlnr.vuln_heuristics import get_external_hits
from vlnr.vuln_ast import ast_taint_scan, ast_bypass_scan
from vlnr.vuln_slice import construct_slices
from vlnr.vuln_scorer import score_slice
from vlnr.vuln_models import PackageFindings, TriageInfo, PoCData, Slice, ToolHit, DataflowNode


class TimeoutException(Exception):
    pass


def timeout_handler(signum: int, frame: Any) -> None:
    raise TimeoutException


SKIP_DIRS = {
    "fixtures",
    "resources",
    "data",
    "snippets",
    "site-packages",
    ".venv",
    "node_modules",
    "tests",
    "__pycache__",
    ".git",
}


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """Configures logging to both console and a timestamped file."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_dir = "logs/scan"
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f"scan_{timestamp}.log")

    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level)

    # File handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)  # Always log DEBUG to file

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)

    # Suppress noise from third-party libs
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)

    return logging.getLogger(__name__)


logger = setup_logging()


def create_slice_from_hit(hit: ToolHit, pkg_name: str, pkg_version: str, local_path: str) -> Slice:
    rel_p = hit.file
    # tool hit might have absolute or relative path depending on tool output
    if os.path.isabs(rel_p):
        rel_p = os.path.relpath(rel_p, local_path)

    return Slice(
        slice_id=str(uuid.uuid4()),
        package=pkg_name,
        version=pkg_version,
        category=[hit.rule],
        sink_api=hit.message.split(":")[0],  # Rough heuristic
        static_class="suspicious",
        risk_score_static=0.7 if hit.severity in ["HIGH", "ERROR"] else 0.5,
        dataflow_summary=[DataflowNode(file=rel_p, line=hit.line, expr=hit.message)],
        tool_hits=[hit],
    )


def process_package(
    pkg: dict[str, Any],
    out_dir: str,
    max_files: int = 0,
    llm_client: LLMClient | None = None,
    generate_pocs: bool = False,
) -> PackageFindings | None:
    name = str(pkg["name"])
    version = str(pkg["version"])
    repo_url = pkg.get("repo_url", "")

    source = fetch_source(name, version, repo_url)
    if not source:
        return None

    try:
        local_path = source.local_path

        # 1. Entry points
        eps = discover_entrypoints(local_path)
        logger.info(f"Discovered {len(eps)} entry points for {name}")

        # 1.5 Metadata scan
        # Search for .dist-info/METADATA
        metadata_signals = []
        for dist_info in Path(local_path).rglob("*.dist-info"):
            if dist_info.is_dir():
                metadata_signals.extend(scan_metadata(dist_info))
        if metadata_signals:
            logger.info(f"Metadata scan found {len(metadata_signals)} signals for {name}")

        # 2. External hits
        external_hits = get_external_hits(local_path)
        logger.info(f"External tools found {len(external_hits)} hits for {name}")

        # 3. AST Scan
        all_slices = []
        files_scanned = 0

        # Set up signal for timeout
        signal.signal(signal.SIGALRM, timeout_handler)

        for root, dirs, files in os.walk(local_path):
            # Prune directories
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            for f in files:
                if f.endswith(".py"):
                    if max_files > 0 and files_scanned >= max_files:
                        break
                    files_scanned += 1
                    full_p = os.path.join(root, f)
                    rel_p = os.path.relpath(full_p, local_path)
                    try:
                        with open(full_p, "r", encoding="utf-8", errors="ignore") as f_obj:
                            content = f_obj.read()

                            # Timeout for parsing
                            signal.alarm(5)
                            try:
                                tree = ast.parse(content)
                            finally:
                                signal.alarm(0)

                            slices = ast_taint_scan(tree, name, version, rel_p)
                            all_slices.extend(slices)

                            # Bypass scan for top-level execution
                            # Target __init__.py, tests/, conftest.py, and other sensitive areas
                            if (
                                f == "__init__.py"
                                or "tests/" in rel_p
                                or f == "conftest.py"
                                or f == "setup.py"
                                or f == "METADATA"
                            ):
                                bypass_slices = ast_bypass_scan(tree, name, version, rel_p)
                                all_slices.extend(bypass_slices)
                    except TimeoutException:
                        logger.error(f"Parsing timed out for {full_p}")
                    except Exception as e:
                        logger.error(f"Failed to parse {full_p}: {e}")
            if max_files > 0 and files_scanned >= max_files:
                break

        # 3.5 External hits fallback slicing
        # If an external hit isn't matched by any AST slice, create a new slice for it.
        for hit in external_hits:
            matched = False
            for s in all_slices:
                if (
                    s.dataflow_summary
                    and hit.file.endswith(s.dataflow_summary[-1].file)
                    and hit.line == s.dataflow_summary[-1].line
                ):
                    matched = True
                    break
            if not matched:
                logger.debug(f"Creating slice from external hit: {hit.tool} {hit.rule} at {hit.file}:{hit.line}")
                all_slices.append(create_slice_from_hit(hit, name, version, local_path))

        # 4. Refine slices with external hits and scoring
        # 4.1 Conjunctive Bypass Logic: Escalation for co-occurring signals
        # We look for signals in the same file or package that reinforce each other
        signals_by_file: dict[str, list[Slice]] = {}
        for s in all_slices:
            if s.dataflow_summary:
                fname = s.dataflow_summary[-1].file
                signals_by_file.setdefault(fname, []).append(s)

        for fname, signals in signals_by_file.items():
            # Example pairs: base64 + exec/eval, network call + dynamic import
            has_obfuscation = any("base64" in s.sink_api or "b64" in s.sink_api for s in signals)
            has_execution = any(s.sink_api in ["eval", "exec", "os.system"] for s in signals)
            has_network = any("requests" in s.sink_api or "urllib" in s.sink_api for s in signals)
            
            # Check for metadata signals too
            has_suspicious_metadata = any(sig.severity == "HIGH" for sig in metadata_signals)

            if (has_obfuscation and has_execution) or (has_network and has_execution) or (has_suspicious_metadata and has_execution):
                for s in signals:
                    if s.sink_api in ["eval", "exec", "os.system", "base64.b64decode"]:
                        s.static_class = "obvious_vuln"
                        s.risk_score_static = 0.95
                        if "Conjunctive Escalation" not in s.category:
                            s.category.append("Conjunctive Escalation")

        for s in all_slices:
            # Match external hits by file and line
            s.tool_hits = (
                [
                    h
                    for h in external_hits
                    if h.file.endswith(s.dataflow_summary[-1].file) and h.line == s.dataflow_summary[-1].line
                ]
                if s.dataflow_summary
                else []
            )
            s.risk_score_static = score_slice(s)
            # Add bonus for tool agreement
            if s.tool_hits:
                s.risk_score_static = min(1.0, s.risk_score_static + 0.1)

        # 5. Construct snippets
        all_slices = construct_slices(all_slices, local_path)

        # 5.5 LLM Triage
        if llm_client:
            # Filter slices for triage
            to_triage = [s for s in all_slices if s.risk_score_static > 0.3 or s.tool_hits]

            if to_triage:
                logger.info(f"Triaging {len(to_triage)} slices for {name} using LLM batching")

                # Batch processing
                batch_size = 10
                for i in range(0, len(to_triage), batch_size):
                    batch_slices = to_triage[i : i + batch_size]
                    batch_items = []
                    for s in batch_slices:
                        source_snippet = next((c["code"] for c in s.code_snippets if "source" in c.get("tags", [])), "")
                        sink_snippet = next((c["code"] for c in s.code_snippets if "sink" in c.get("tags", [])), "")
                        hit_msg = s.tool_hits[0].message if s.tool_hits else f"Static risk: {s.risk_score_static}"
                        location = (
                            f"{s.dataflow_summary[-1].file}:{s.dataflow_summary[-1].line}"
                            if s.dataflow_summary
                            else "unknown"
                        )

                        batch_items.append(
                            {
                                "slice_id": s.slice_id,
                                "hit_message": hit_msg,
                                "source_code": source_snippet,
                                "sink_code": sink_snippet,
                                "file_line": location,
                            }
                        )

                    try:
                        batch_res = triage_vulnerabilities_batch(batch_items, llm_client)

                        # Map results back to slices
                        res_map = {r.slice_id: r for r in batch_res.results}
                        for s in batch_slices:
                            if s.slice_id in res_map:
                                res = res_map[s.slice_id]
                                s.triage_info = TriageInfo(**res.model_dump())
                                s.triage_score = res.plausibility

                                logger.debug(
                                    f"Slice {s.slice_id} triaged: score={s.triage_score:.2f}, plausible={not res.is_false_positive}"
                                )

                                # Deep reasoning and PoC generation for high-confidence findings
                                if generate_pocs and s.triage_score > 0.7:
                                    logger.info(f"Generating PoC for high-confidence slice {s.slice_id}")
                                    vuln_ctx = (
                                        f"Analysis: {res.analysis}\nTool Hit: {s.tool_hits[0].message if s.tool_hits else 'N/A'}\n"
                                        f"Source: {next((c['code'] for c in s.code_snippets if 'source' in c.get('tags', [])), '')}\n"
                                        f"Sink: {next((c['code'] for c in s.code_snippets if 'sink' in c.get('tags', [])), '')}"
                                    )
                                    poc_res = generate_poc(name, vuln_ctx, llm_client)
                                    s.poc_data = PoCData(**poc_res.model_dump())
                            else:
                                logger.warning(f"No triage result returned for slice {s.slice_id} in batch")
                    except Exception as e:
                        logger.error(f"Batch triage failed: {e}")
            else:
                logger.info(f"No slices meet triage threshold for {name}")

        # 6. Save results
        findings_path = os.path.join(out_dir, f"{name}-findings.json")
        slices_path = os.path.join(out_dir, f"{name}-slices.jsonl")

        findings = PackageFindings(
            package=pkg,
            sinks=[s.model_dump() for s in all_slices],
            metadata_signals=[s.__dict__ for s in metadata_signals],
            stats={
                "num_sinks_total": len(all_slices),
                "num_obvious_vuln": len([s for s in all_slices if s.static_class == "obvious_vuln"]),
                "num_bandit_hits": len([h for h in external_hits if h.tool == "bandit"]),
            },
        )

        with open(findings_path, "w") as f_findings:
            json.dump(findings.model_dump(), f_findings, indent=2)

        with open(slices_path, "w") as f_slices:
            for s in all_slices:
                f_slices.write(json.dumps(s.model_dump()) + "\n")

        logger.info(f"Finished processing {name}. Found {len(all_slices)} potential vulnerabilities.")
        return findings

    finally:
        cleanup_source(source)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("candidates", help="Path to candidates.json")
    parser.add_argument("--out-dir", default="findings", help="Output directory")
    parser.add_argument("--max-packages", type=int, default=0, help="Max packages to process")
    parser.add_argument("--max-files-per-pkg", type=int, default=0, help="Max files to scan per package")
    parser.add_argument("--llm-triage", action="store_true", help="Use LLM to triage findings")
    parser.add_argument(
        "--llm-poc", action="store_true", help="Generate PoC for high-confidence findings (requires --llm-triage)"
    )
    args = parser.parse_args()

    if not os.path.exists(args.out_dir):
        os.makedirs(args.out_dir)

    llm_client: Optional[LLMClient] = None
    if args.llm_triage or args.llm_poc:
        try:
            llm_client = LLMClient()
            logger.info("LLM Client enabled for triage/PoC. Using NVIDIA NIM.")
        except Exception as e:
            logger.error(f"Failed to initialize LLM client: {e}. Proceeding without LLM features.")
            args.llm_triage = False
            args.llm_poc = False

    with open(args.candidates, "r") as f:
        candidates = json.load(f)

    if args.max_packages > 0:
        candidates = candidates[: args.max_packages]

    global_index = []

    for pkg in candidates:
        try:
            findings = process_package(
                pkg,
                args.out_dir,
                max_files=args.max_files_per_pkg,
                llm_client=llm_client if args.llm_triage or args.llm_poc else None,
                generate_pocs=args.llm_poc,
            )
            if findings:
                global_index.append({"package": pkg["name"], "version": pkg["version"], "stats": findings.stats})
        except Exception as e:
            logger.exception(f"Failed to process {pkg['name']}: {e}")

    index_path = os.path.join(args.out_dir, "all-findings-index.json")
    with open(index_path, "w") as f_index:
        json.dump(global_index, f_index, indent=2)


if __name__ == "__main__":
    main()
