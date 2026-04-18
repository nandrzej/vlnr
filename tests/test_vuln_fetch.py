import os
import shutil
import subprocess
import tempfile
import pytest
import typing

from vlnr.vuln_fetch import fetch_source, cleanup_source


@pytest.fixture
def local_git_repo() -> typing.Generator[str, None, None]:
    repo_dir = tempfile.mkdtemp()

    def run_git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=repo_dir, check=True, capture_output=True)

    run_git("init")
    run_git("config", "user.name", "Test User")
    run_git("config", "user.email", "test@example.com")

    with open(os.path.join(repo_dir, "main.py"), "w") as f:
        f.write("print('v1.0')\n")
    run_git("add", "main.py")
    run_git("commit", "-m", "Initial commit")
    run_git("tag", "v1.0")

    yield f"file://{repo_dir}"

    shutil.rmtree(repo_dir)


def test_fetch_source_success(local_git_repo: str) -> None:
    source = fetch_source("test-pkg", "1.0", local_git_repo)
    assert source is not None
    assert source.package == "test-pkg"
    assert source.version == "1.0"

    with open(os.path.join(source.local_path, "main.py"), "r") as f:
        assert "v1.0" in f.read()

    cleanup_source(source)
    assert not os.path.exists(source.local_path)
