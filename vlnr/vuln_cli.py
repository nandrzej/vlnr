import json
import logging
import os
import ast
from typing import Any
from vlnr.vuln_fetch import fetch_source, cleanup_source
from vlnr.vuln_entrypoints import discover_entrypoints
from vlnr.vuln_heuristics import get_external_hits
from vlnr.vuln_ast import ast_taint_scan
from vlnr.vuln_slice import construct_slices
from vlnr.vuln_scorer import score_slice
from vlnr.vuln_models import PackageFindings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def process_package(pkg: dict[str, Any], out_dir: str) -> None:
    name = str(pkg["name"])
    version = str(pkg["version"])
    repo_url = pkg.get("repo_url", "")

    source = fetch_source(name, version, repo_url)
    if not source:
        return

    try:
        local_path = source.local_path
        
        # 1. Entry points
        eps = discover_entrypoints(local_path)
        logger.info(f"Discovered {len(eps)} entry points for {name}")

        # 2. External hits
        external_hits = get_external_hits(local_path)
        logger.info(f"External tools found {len(external_hits)} hits for {name}")

        # 3. AST Scan
        all_slices = []
        for root, _, files in os.walk(local_path):
            if "tests" in root.split(os.sep):
                continue
            for f in files:
                if f.endswith(".py"):
                    full_p = os.path.join(root, f)
                    rel_p = os.path.relpath(full_p, local_path)
                    try:
                        with open(full_p, "r") as f_obj:
                            tree = ast.parse(f_obj.read())
                            slices = ast_taint_scan(tree, name, version, rel_p)
                            all_slices.extend(slices)
                    except Exception as e:
                        logger.error(f"Failed to parse {full_p}: {e}")

        # 4. Refine slices with external hits and scoring
        for s in all_slices:
            # Match external hits by file and line
            s.tool_hits = [h for h in external_hits if h.file.endswith(s.dataflow_summary[-1].file) and h.line == s.dataflow_summary[-1].line] if s.dataflow_summary else []
            s.risk_score_static = score_slice(s)
            # Add bonus for tool agreement
            if s.tool_hits:
                s.risk_score_static = min(1.0, s.risk_score_static + 0.1)

        # 5. Construct snippets
        all_slices = construct_slices(all_slices, local_path)

        # 6. Save results
        findings_path = os.path.join(out_dir, f"{name}-findings.json")
        slices_path = os.path.join(out_dir, f"{name}-slices.jsonl")
        
        findings = PackageFindings(
            package=pkg,
            sinks=[s.model_dump() for s in all_slices],
            stats={
                "num_sinks_total": len(all_slices),
                "num_obvious_vuln": len([s for s in all_slices if s.static_class == "obvious_vuln"]),
                "num_bandit_hits": len([h for h in external_hits if h.tool == "bandit"])
            }
        )
        
        with open(findings_path, "w") as f_findings:
            json.dump(findings.model_dump(), f_findings, indent=2)
        
        with open(slices_path, "w") as f_slices:
            for s in all_slices:
                f_slices.write(json.dumps(s.model_dump()) + "\n")

        logger.info(f"Finished processing {name}. Found {len(all_slices)} potential vulnerabilities.")

    finally:
        cleanup_source(source)

def main() -> None:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("candidates", help="Path to candidates.json")
    parser.add_argument("--out-dir", default="findings", help="Output directory")
    args = parser.parse_args()

    if not os.path.exists(args.out_dir):
        os.makedirs(args.out_dir)

    with open(args.candidates, "r") as f:
        candidates = json.load(f)

    for pkg in candidates:
        try:
            process_package(pkg, args.out_dir)
        except Exception as e:
            logger.exception(f"Failed to process {pkg['name']}: {e}")

if __name__ == "__main__":
    main()
