import vcr
import os
import pytest
from dotenv import load_dotenv

load_dotenv()


@pytest.fixture(scope="session")
def my_vcr() -> vcr.VCR:
    # Allow overriding record mode via environment variable (e.g. VCR_RECORD_MODE=all)
    record_mode = os.environ.get("VCR_RECORD_MODE", "once")
    return vcr.VCR(
        cassette_library_dir="tests/cassettes",
        record_mode=record_mode,
        filter_headers=[("authorization", "Bearer <REDACTED>")],
        filter_query_parameters=["api_key"],
        match_on=["method", "scheme", "host", "port", "path", "query", "body"],
    )


@pytest.fixture(autouse=True)
def env_setup() -> None:
    # Ensure LLM_API_KEY is present for tests but use a dummy if not in CI/Local
    if not os.environ.get("LLM_API_KEY"):
        os.environ["LLM_API_KEY"] = "nvapi-dummy-key-for-tests"
    if not os.environ.get("LLM_BASE_URL"):
        os.environ["LLM_BASE_URL"] = "https://integrate.api.nvidia.com/v1"
