import re
from pathlib import Path
from dataclasses import dataclass
from email.parser import Parser


@dataclass
class MetadataSignal:
    field: str
    pattern_matched: str
    severity: str


def scan_metadata(dist_info_dir: Path) -> list[MetadataSignal]:
    """
    Scan .dist-info/METADATA for suspicious patterns.
    """
    metadata_file = dist_info_dir / "METADATA"
    if not metadata_file.exists():
        return []

    signals: list[MetadataSignal] = []

    try:
        with metadata_file.open("r", encoding="utf-8", errors="ignore") as f:
            msg = Parser().parse(f)
    except Exception:
        return []

    # Patterns to scan
    shell_patterns = [
        (re.compile(r"curl\s+http", re.I), "curl"),
        (re.compile(r"wget\s+http", re.I), "wget"),
        (re.compile(r"\|\s*sh\b", re.I), "| sh"),
        (re.compile(r"\|\s*bash\b", re.I), "| bash"),
        (re.compile(r"bash\s+-c", re.I), "bash -c"),
    ]

    suspicious_url_patterns = [
        (re.compile(r"http://(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\d+", re.I), "Non-standard IP/numeric host"),
        (re.compile(r"http://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.I), "Raw IP address"),
    ]

    # Base64 pattern: long strings of alphanumeric + / + + + =
    # We look for 20+ chars that look like base64
    base64_pattern = re.compile(r"[a-zA-Z0-9+/]{20,}=*")

    fields_to_scan = ["Description", "Summary", "Home-page"]

    # Description can be in the body of the RFC 822 message
    scan_targets = []
    for field in fields_to_scan:
        val = msg.get(field)
        if val:
            scan_targets.append((field, val))

    body = msg.get_payload()
    if isinstance(body, str) and body:
        scan_targets.append(("Description (Body)", body))

    for field, text in scan_targets:
        # Shell commands
        for pattern, label in shell_patterns:
            if pattern.search(text):
                signals.append(MetadataSignal(field=field, pattern_matched=label, severity="HIGH"))

        # Suspicious URLs
        for pattern, label in suspicious_url_patterns:
            match = pattern.search(text)
            if match:
                signals.append(MetadataSignal(field=field, pattern_matched=match.group(), severity="MEDIUM"))

        # Encoded payloads
        if field in ["Summary", "Description", "Description (Body)"]:
            matches = base64_pattern.findall(text)
            for m in matches:
                # Basic heuristic: if it contains mixed case and numbers and is long, it's suspicious
                if any(c.islower() for c in m) and any(c.isupper() for c in m) and any(c.isdigit() for c in m):
                    signals.append(
                        MetadataSignal(field=field, pattern_matched="base64-like string", severity="MEDIUM (Encoded)")
                    )

    return signals
