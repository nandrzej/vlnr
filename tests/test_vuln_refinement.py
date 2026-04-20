from vlnr.vuln_fetch import refine_repo_url


def test_refine_repo_url_github_tree() -> None:
    url = "https://github.com/langchain-ai/langgraph/tree/main/libs/prebuilt"
    expected = "https://github.com/langchain-ai/langgraph"
    assert refine_repo_url(url) == expected


def test_refine_repo_url_github_blob() -> None:
    url = "https://github.com/user/repo/blob/master/file.py"
    expected = "https://github.com/user/repo"
    assert refine_repo_url(url) == expected


def test_refine_repo_url_gitlab() -> None:
    url = "https://gitlab.com/group/project/-/tree/main"
    expected = "https://gitlab.com/group/project"
    assert refine_repo_url(url) == expected


def test_refine_repo_url_clean() -> None:
    url = "https://github.com/psf/requests"
    assert refine_repo_url(url) == url


def test_refine_repo_url_empty() -> None:
    assert refine_repo_url("") == ""
    # The function handles None at runtime but we'll stick to str for the test to satisfy mypy.
    assert refine_repo_url("") == ""
