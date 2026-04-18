import os
from typing import Any, Optional
from vlnr.vuln_models import Slice


def construct_slices(slices: list[Slice], local_path: str) -> list[Slice]:
    """
    Fills code_snippets for each slice by reading files from local_path.
    """
    for s in slices:
        seen_snippets = set()
        sorted_nodes = sorted(s.dataflow_summary, key=lambda n: n.line)

        for node in sorted_nodes:
            snippet_key = (node.file, node.line)
            if snippet_key in seen_snippets:
                continue

            snippet = get_snippet(local_path, node.file, node.line)
            if snippet:
                s.code_snippets.append(snippet)
                seen_snippets.add(snippet_key)

        if len(s.code_snippets) > 5:
            first = s.code_snippets[0]
            last = s.code_snippets[-1]
            middle_idx = len(s.code_snippets) // 2
            middle = s.code_snippets[middle_idx]
            s.code_snippets = [first, middle, last]

    return slices


def get_snippet(local_path: str, filename: str, line: int) -> Optional[dict[str, Any]]:
    """Reads file and returns snippet around line."""
    full_path = os.path.join(local_path, filename)
    if not os.path.exists(full_path):
        return None

    try:
        with open(full_path, "r") as f:
            lines = f.readlines()

            start = max(0, line - 11)  # 1-indexed line
            end = min(len(lines), line + 10)

            content = "".join(lines[start:end])
            return {"file": filename, "line": line, "content": content, "start_line": start + 1}
    except Exception:
        return None
