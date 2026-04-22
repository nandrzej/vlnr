"""Validate PoC scripts inside disposable Docker containers."""

import logging
import re
import threading
import uuid
from typing import Literal

import docker
from docker.errors import DockerException, NotFound
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class ContainerIsolationError(Exception):
    """Raised when the Docker daemon is unavailable or container isolation fails."""


def check_docker_available() -> None:
    """Verify the Docker daemon is reachable.

    Raises ContainerIsolationError if Docker is unavailable,
    never falls back to any other execution method.
    """
    try:
        client = docker.from_env()
        client.ping()
    except DockerException as exc:
        raise ContainerIsolationError(str(exc)) from exc


class ValidationResult(BaseModel):
    status: Literal["Runtime_Reachable", "Runtime_Failed", "Runtime_Error", "Runtime_Timeout"]
    exit_code: int | None
    stdout: str
    stderr: str
    expected_output_matched: bool


def validate_poc_in_container(
    poc_code: str,
    package_name: str,
    package_version: str,
    timeout: int = 30,
    expected_output: str | None = None,
    expected_exception: str | None = None,
) -> ValidationResult:
    """Run a PoC script inside a fresh Docker container and report results.

    Creates a python:3.12-slim container, installs the target package,
    executes the PoC, and always cleans up the container.
    """
    check_docker_available()

    container_name = f"vlnr-poc-{uuid.uuid4().hex[:12]}"
    client = docker.from_env()

    container = client.containers.create(
        "python:3.12-slim",
        name=container_name,
        command="sleep infinity",
        detach=True,
    )
    container.start()

    try:
        _install_package(container, package_name, package_version)

        exit_code: int | None = None
        stdout = ""
        stderr = ""
        timed_out = False

        result_holder: list[tuple[int, tuple[bytes | None, bytes | None]]] = []

        def run_poc() -> None:
            ec, output = container.exec_run(
                cmd=["python", "-c", poc_code],
                demux=True,
            )
            result_holder.append((ec, output))

        thread = threading.Thread(target=run_poc, daemon=True)
        thread.start()
        thread.join(timeout=timeout)

        if thread.is_alive():
            timed_out = True
            # The thread is daemonized and the container will be removed in finally,
            # which will terminate the exec_run call.
        else:
            exit_code, (stdout_bytes, stderr_bytes) = result_holder[0]
            if stdout_bytes is not None:
                stdout = stdout_bytes.decode("utf-8", errors="replace")
            if stderr_bytes is not None:
                stderr = stderr_bytes.decode("utf-8", errors="replace")

        if timed_out:
            return ValidationResult(
                status="Runtime_Timeout",
                exit_code=None,
                stdout=stdout,
                stderr=stderr,
                expected_output_matched=False,
            )

        assert exit_code is not None  # guaranteed when not timed out

        # Determine expected_output_matched
        expected_output_matched = _check_expectation(
            exit_code,
            stdout,
            stderr,
            expected_output,
            expected_exception,
        )

        # Determine status
        if exit_code == 0:
            status: Literal["Runtime_Reachable", "Runtime_Failed", "Runtime_Error", "Runtime_Timeout"] = (
                "Runtime_Reachable" if expected_output_matched else "Runtime_Failed"
            )
        elif expected_exception is not None and expected_exception in stderr:
            status = "Runtime_Reachable"
        else:
            status = "Runtime_Error"

        return ValidationResult(
            status=status,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            expected_output_matched=expected_output_matched,
        )
    finally:
        _cleanup_container(container, container_name)


def _install_package(
    container: docker.models.containers.Container,
    package_name: str,
    package_version: str,
) -> None:
    """Install the target package inside the container. Best-effort."""
    # Strict validation of package name and version to prevent command injection
    if not re.match(r"^[a-zA-Z0-9._-]+$", package_name) or not re.match(
        r"^[a-zA-Z0-9._-]+$", package_version
    ):
        logger.warning(
            "Invalid package name or version: %s==%s; skipping installation",
            package_name,
            package_version,
        )
        return

    try:
        container.exec_run(
            cmd=["pip", "install", "--quiet", "--", f"{package_name}=={package_version}"],
        )
    except DockerException:
        logger.warning(
            "pip install %s==%s failed; proceeding without package",
            package_name,
            package_version,
        )


def _check_expectation(
    exit_code: int,
    stdout: str,
    stderr: str,
    expected_output: str | None,
    expected_exception: str | None,
) -> bool:
    """Determine whether the PoC output matched expectations."""
    if expected_output is not None:
        return expected_output in stdout
    if expected_exception is not None:
        return expected_exception in stderr
    return True


def _cleanup_container(
    container: docker.models.containers.Container,
    container_name: str,
) -> None:
    """Stop and remove a container, ignoring if already gone."""
    try:
        container.stop(timeout=2)
    except NotFound:
        pass
    except DockerException:
        pass
    try:
        container.remove(force=True)
    except NotFound:
        pass
    except DockerException:
        pass
