import json
import logging
import shutil
import subprocess
from vlnr.vuln_models import ToolHit

logger = logging.getLogger(__name__)


def ensure_tools() -> None:
    """Ensures bandit, ruff, and semgrep are installed."""
    tools = ["bandit", "ruff", "semgrep"]
    missing = [t for t in tools if shutil.which(t) is None]
    if missing:
        logger.info(f"Installing missing tools: {missing}")
        subprocess.run(["uv", "pip", "install"] + missing, check=True)


def run_bandit(local_path: str) -> list[ToolHit]:
    hits = []
    try:
        result = subprocess.run(["bandit", "-r", local_path, "-f", "json", "-q"], capture_output=True, text=True)
        if result.stdout:
            data = json.loads(result.stdout)
            for issue in data.get("results", []):
                hits.append(
                    ToolHit(
                        tool="bandit",
                        rule=issue.get("test_id", "unknown"),
                        severity=issue.get("issue_severity", "LOW"),
                        message=issue.get("issue_text", ""),
                        file=issue.get("filename", ""),
                        line=issue.get("line_number", 0),
                    )
                )
    except Exception as e:
        logger.error(f"Bandit failed: {e}")
    return hits


def run_ruff(local_path: str) -> list[ToolHit]:
    hits = []
    try:
        result = subprocess.run(
            ["ruff", "check", local_path, "--select", "S", "--output-format", "json"], capture_output=True, text=True
        )
        if result.stdout:
            data = json.loads(result.stdout)
            for issue in data:
                hits.append(
                    ToolHit(
                        tool="ruff",
                        rule=issue.get("code", "unknown"),
                        severity="HIGH",
                        message=issue.get("message", ""),
                        file=issue.get("filename", ""),
                        line=issue.get("location", {}).get("row", 0),
                    )
                )
    except Exception as e:
        logger.error(f"Ruff failed: {e}")
    return hits


def run_semgrep(local_path: str) -> list[ToolHit]:
    hits = []
    try:
        cmd = [
            "semgrep",
            "scan",
            local_path,
            "--config",
            "p/python",
            "--config",
            "vlnr/rules/",
            "--json",
            "-q",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.stdout:
            data = json.loads(result.stdout)
            for issue in data.get("results", []):
                hits.append(
                    ToolHit(
                        tool="semgrep",
                        rule=issue.get("check_id", "unknown"),
                        severity=issue.get("extra", {}).get("severity", "LOW"),
                        message=issue.get("extra", {}).get("message", ""),
                        file=issue.get("path", ""),
                        line=issue.get("start", {}).get("line", 0),
                    )
                )
    except Exception as e:
        logger.error(f"Semgrep failed: {e}")
    return hits


def get_external_hits(local_path: str) -> list[ToolHit]:
    ensure_tools()
    all_hits = []
    all_hits.extend(run_bandit(local_path))
    all_hits.extend(run_ruff(local_path))
    all_hits.extend(run_semgrep(local_path))
    return all_hits
