"""Tests for vlnr.vuln_validate — PoC validation via Docker containers.

Integration tests require OrbStack (or any Docker daemon) with python:3.12-slim.
Run only unit/mock tests: pytest -m "not integration"
"""

from unittest.mock import patch

import pytest

from vlnr.vuln_validate import (
    ContainerIsolationError,
    check_docker_available,
    validate_poc_in_container,
    ValidationResult,
)


# ---------------------------------------------------------------------------
# Unit tests (Docker unavailable / mocked)
# ---------------------------------------------------------------------------


class TestDockerUnavailable:
    """Verify the pipeline fails explicitly when container runtime is absent."""

    def test_docker_unavailable_raises_error(self) -> None:
        """check_docker_available() must raise ContainerIsolationError,
        not the raw DockerException, so callers get a domain-specific signal."""
        import docker as _docker

        with patch(
            "vlnr.vuln_validate.docker.from_env",
            side_effect=_docker.errors.DockerException("no daemon"),
        ):
            with pytest.raises(ContainerIsolationError):
                check_docker_available()

    def test_no_venv_fallback(self) -> None:
        """validate_poc_in_container() MUST NOT silently degrade to venv
        execution when Docker is unavailable. It must raise
        ContainerIsolationError so the caller knows validation did not happen."""
        import docker as _docker

        with patch(
            "vlnr.vuln_validate.docker.from_env",
            side_effect=_docker.errors.DockerException("no daemon"),
        ):
            with pytest.raises(ContainerIsolationError):
                validate_poc_in_container(
                    poc_code="print('should not run')",
                    package_name="dummy",
                    package_version="0.0.0",
                )


# ---------------------------------------------------------------------------
# Integration tests (real Docker)
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDockerAvailable:
    """Requires a running Docker daemon with python:3.12-slim."""

    def test_docker_available(self) -> None:
        """With a live daemon, check_docker_available() completes without error."""
        check_docker_available()  # should not raise


@pytest.mark.integration
class TestValidatePocInContainer:
    """Integration tests exercising real container runs."""

    def test_validate_poc_simple(self) -> None:
        """Simple PoC that prints expected output → Runtime_Reachable + matched."""
        result = validate_poc_in_container(
            poc_code="print('VULN_CONFIRMED')",
            package_name="pip",
            package_version="24.0",
            expected_output="VULN_CONFIRMED",
        )
        assert isinstance(result, ValidationResult)
        assert result.status == "Runtime_Reachable"
        assert result.expected_output_matched is True
        assert result.exit_code == 0

    def test_validate_poc_expected_exception(self) -> None:
        """PoC that raises the expected exception → Runtime_Reachable + matched."""
        result = validate_poc_in_container(
            poc_code="raise ValueError('expected vuln error')",
            package_name="pip",
            package_version="24.0",
            expected_exception="ValueError",
        )
        assert result.status == "Runtime_Reachable"
        assert result.expected_output_matched is True

    def test_validate_poc_timeout(self) -> None:
        """PoC that sleeps past the deadline → Runtime_Timeout.
        The container must be stopped/removed (no zombie containers)."""
        result = validate_poc_in_container(
            poc_code="import time; time.sleep(60)",
            package_name="pip",
            package_version="24.0",
            timeout=5,
        )
        assert result.status == "Runtime_Timeout"

    def test_validate_poc_runtime_error(self) -> None:
        """PoC referencing a non-existent module → Runtime_Error, non-zero exit."""
        result = validate_poc_in_container(
            poc_code="import nonexistent_module_xyz",
            package_name="pip",
            package_version="24.0",
        )
        assert result.status == "Runtime_Error"
        assert result.exit_code != 0

    def test_validate_poc_wrong_output(self) -> None:
        """PoC produces output that doesn't match expected → matched=False.
        Status is Runtime_Failed because the specific expectation was not met."""
        result = validate_poc_in_container(
            poc_code="print('wrong')",
            package_name="pip",
            package_version="24.0",
            expected_output="VULN_CONFIRMED",
        )
        assert result.status == "Runtime_Failed"
        assert result.expected_output_matched is False

    def test_container_cleanup_on_failure(self) -> None:
        """Even when the PoC crashes, the container must not be left behind.
        We look for containers with the vlnr naming prefix after the run."""
        result = validate_poc_in_container(
            poc_code="import nonexistent_module_xyz",
            package_name="pip",
            package_version="24.0",
        )
        assert result.status == "Runtime_Error"

        # Verify no vlnr-prefixed containers are lingering
        import docker as _docker

        client = _docker.from_env()
        containers = client.containers.list(all=True, filters={"name": "vlnr"})
        vlnr_containers = [c for c in containers if c.name.startswith("vlnr-poc")]
        assert len(vlnr_containers) == 0, f"Leftover containers: {[c.name for c in vlnr_containers]}"

    def test_validate_poc_multiline(self) -> None:
        """Multiline PoC code must execute correctly."""
        poc = """
x = 1
y = 2
print(f'RESULT:{x + y}')
"""
        result = validate_poc_in_container(
            poc_code=poc,
            package_name="pip",
            package_version="24.0",
            expected_output="RESULT:3",
        )
        assert result.status == "Runtime_Reachable"
        assert result.expected_output_matched is True

    def test_validate_poc_long_output(self) -> None:
        """PoC that produces very long output — must capture it fully."""
        poc = "print('A' * 10000)"
        result = validate_poc_in_container(
            poc_code=poc,
            package_name="pip",
            package_version="24.0",
            expected_output="A" * 10000,
        )
        assert result.status == "Runtime_Reachable"
        assert result.expected_output_matched is True

    def test_validate_poc_unique_container_names(self) -> None:
        """Two concurrent/sequential runs must not collide on container names.
        validate_poc_in_container must use unique container names."""
        # Run twice with the same parameters; both must succeed without
        # name-collision errors.
        r1 = validate_poc_in_container(
            poc_code="print('first')",
            package_name="pip",
            package_version="24.0",
        )
        r2 = validate_poc_in_container(
            poc_code="print('second')",
            package_name="pip",
            package_version="24.0",
        )
        assert r1.status == "Runtime_Reachable"
        assert r2.status == "Runtime_Reachable"

    def test_validate_poc_package_version_special_chars(self) -> None:
        """Package versions with special characters (e.g. pre-release tags)
        must not break container setup."""
        # Using a pre-release style version string; pip install will fail
        # but the container should still run and report Runtime_Error
        # (not crash the orchestrator).
        result = validate_poc_in_container(
            poc_code="print('ok')",
            package_name="pip",
            package_version="24.0rc1",
        )
        # Version may or may not resolve; either way, the function must
        # return a ValidationResult, not raise an unhandled exception.
        assert isinstance(result, ValidationResult)
