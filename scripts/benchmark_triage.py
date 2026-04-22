import json
import logging
import argparse
from typing import List, Dict
from vlnr.llm import LLMClient
from vlnr.triage import triage_vulnerabilities_batch

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_ground_truth(path: str) -> List[Dict]:
    with open(path, "r") as f:
        return [json.loads(line) for line in f]


def compute_metrics(results: List[Dict], ground_truth: Dict[str, bool], threshold: float):
    tp = 0
    fp = 0
    tn = 0
    fn = 0

    for res in results:
        slice_id = res["slice_id"]
        is_vuln_gt = ground_truth[slice_id]
        is_vuln_pred = res["plausibility"] >= threshold

        if is_vuln_gt and is_vuln_pred:
            tp += 1
        elif not is_vuln_gt and is_vuln_pred:
            fp += 1
        elif not is_vuln_gt and not is_vuln_pred:
            tn += 1
        elif is_vuln_gt and not is_vuln_pred:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    return {
        "threshold": threshold,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default="tests/data/ground_truth_slices.jsonl")
    parser.add_argument("--mock", help="Use mock results from JSON file")
    args = parser.parse_args()

    items = load_ground_truth(args.data)
    ground_truth = {item["slice_id"]: item["is_vulnerable"] for item in items}

    if args.mock:
        with open(args.mock, "r") as f:
            mock_data = json.load(f)
            from vlnr.models import BatchTriageResult

            batch_result = BatchTriageResult(**mock_data)
    else:
        # Prepare items for triage (remove ground truth)
        triage_items = []
        for item in items:
            triage_items.append(
                {
                    "slice_id": item["slice_id"],
                    "hit_message": item["hit_message"],
                    "source_code": item["source_code"],
                    "sink_code": item["sink_code"],
                    "file_line": item["file_line"],
                }
            )

        client = LLMClient()

        if args.vcr:
            import vcr

            my_vcr = vcr.VCR(
                cassette_library_dir="tests/cassettes",
                record_mode="once",
                match_on=["method", "scheme", "host", "port", "path", "query", "body"],
                filter_headers=["authorization", "api-key", "x-api-key"],
            )
            with my_vcr.use_cassette("triage_benchmark.yaml"):
                batch_result = triage_vulnerabilities_batch(triage_items, client)
        else:
            batch_result = triage_vulnerabilities_batch(triage_items, client)

    results = [res.model_dump() for res in batch_result.results]

    thresholds = [0.4, 0.5, 0.6, 0.7, 0.8]
    print(f"{'Threshold':<10} | {'Precision':<10} | {'Recall':<10} | {'F1':<10} | {'TP/FP/TN/FN'}")
    print("-" * 65)

    for t in thresholds:
        m = compute_metrics(results, ground_truth, t)
        print(
            f"{m['threshold']:<10.1f} | {m['precision']:<10.3f} | {m['recall']:<10.3f} | {m['f1']:<10.3f} | {m['tp']}/{m['fp']}/{m['tn']}/{m['fn']}"
        )


if __name__ == "__main__":
    main()
