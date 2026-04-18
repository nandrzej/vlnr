from vlnr.models import PackageInfo
from vlnr.filters import categorize_package, is_target_category


def test_categorize_package() -> None:
    # Case 1: CLI via classifier
    pkg = PackageInfo(name="mytool", version="1.0", classifiers=["Environment :: Console"])
    tags = categorize_package(pkg)
    assert "cli" in tags

    # Case 2: ML via keyword
    pkg = PackageInfo(name="mllib", version="1.0", summary="A neural network library")
    tags = categorize_package(pkg)
    assert "ml" in tags

    # Case 3: Dev via keyword
    pkg = PackageInfo(name="builder", version="1.0", summary="Deploy manager")
    tags = categorize_package(pkg)
    assert "dev" in tags

    # Case 4: Multiple tags
    pkg = PackageInfo(name="cli-ml", version="1.0", classifiers=["Environment :: Console"], summary="AI training tool")
    tags = categorize_package(pkg)
    assert set(tags) == {"cli", "ml"}


def test_is_target_category() -> None:
    pkg = PackageInfo(name="tool", version="1.0", classifiers=["Environment :: Console"])
    assert is_target_category(pkg, include_cli=True) is True
    assert is_target_category(pkg, include_cli=False, include_ml=True, include_dev=True) is False
