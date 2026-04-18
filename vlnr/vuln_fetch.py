import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class RepoSource:
    package: str
    version: str
    repo_url: str
    local_path: str


def fetch_source(package: str, version: str, repo_url: str) -> Optional[RepoSource]:
    """
    Clones the repository and checks out the specified version.
    Returns RepoSource if successful, None otherwise.
    """
    if not repo_url:
        logger.warning(f"No repo_url for {package}")
        return None

    temp_dir = tempfile.mkdtemp(prefix=f"vlnr-{package}-")
    try:
        # Clone with depth 1
        logger.info(f"Cloning {repo_url} for {package}...")
        subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, temp_dir], check=True, capture_output=True, timeout=60
        )

        # Attempt to checkout version tag
        tags_to_try = [f"v{version}", version]
        checkout_success = False
        for tag in tags_to_try:
            try:
                # Fetch the tag specifically if it wasn't cloned (depth 1 might miss it)
                subprocess.run(
                    ["git", "fetch", "--tags", "--depth", "1", "origin", tag],
                    cwd=temp_dir,
                    check=True,
                    capture_output=True,
                    timeout=30,
                )
                subprocess.run(["git", "checkout", tag], cwd=temp_dir, check=True, capture_output=True, timeout=30)
                checkout_success = True
                logger.info(f"Checked out {tag} for {package}")
                break
            except subprocess.CalledProcessError:
                continue

        if not checkout_success:
            logger.warning(f"Could not checkout version {version} for {package}, using default branch")

        # Verify .py files exist
        has_py_files = False
        for root, _, files in os.walk(temp_dir):
            if "tests" in root.split(os.sep):
                continue
            if any(f.endswith(".py") for f in files):
                has_py_files = True
                break

        if not has_py_files:
            logger.error(f"No .py files found in {package} repo (excluding tests)")
            shutil.rmtree(temp_dir)
            return None

        return RepoSource(package=package, version=version, repo_url=repo_url, local_path=temp_dir)

    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        logger.error(f"Failed to clone/checkout {package}: {e}")
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        return None
    except Exception as e:
        logger.exception(f"Unexpected error fetching {package}: {e}")
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        return None


def cleanup_source(source: RepoSource) -> None:
    """Removes the local clone."""
    if os.path.exists(source.local_path):
        shutil.rmtree(source.local_path)
