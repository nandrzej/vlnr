from vlnr.models import PackageInfo

CLI_CLASSIFIERS = {
    "Environment :: Console",
    "Environment :: Console :: Curses",
    "Topic :: Terminals",
    "Topic :: Utilities",
}
DEV_CLASSIFIERS = {
    "Topic :: Software Development :: Build Tools",
    "Topic :: Software Development :: Libraries :: Python Modules",
    "Topic :: Software Development :: Quality Assurance",
}
ML_CLASSIFIERS = {
    "Topic :: Scientific/Engineering :: Artificial Intelligence",
    "Topic :: Scientific/Engineering :: Information Analysis",
}

CATEGORY_KEYWORDS = {
    "cli": ["cli", "tool", "runner", "backup", "monitor", "lint", "format", "shell", "terminal"],
    "ml": ["ml", "ai", "model", "training", "dataset", "pipeline", "neural", "tensor"],
    "dev": ["deploy", "devops", "manager", "builder", "scaffold", "ci", "cd", "test", "lint"],
}


def categorize_package(pkg: PackageInfo) -> list[str]:
    """Return list of matching category tags."""
    tags = set()

    # Check classifiers
    classifiers = set(pkg.classifiers)
    if classifiers & CLI_CLASSIFIERS:
        tags.add("cli")
    if classifiers & DEV_CLASSIFIERS:
        tags.add("dev")
    if classifiers & ML_CLASSIFIERS:
        tags.add("ml")

    # Check keywords in summary and name
    text = (pkg.name + " " + pkg.summary).lower()
    for cat, keywords in CATEGORY_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            tags.add(cat)

    # Heuristic: console_scripts usually means CLI
    if pkg.console_scripts:
        tags.add("cli")

    return sorted(list(tags))


def is_target_category(
    pkg: PackageInfo, include_cli: bool = True, include_ml: bool = True, include_dev: bool = True
) -> bool:
    """Check if package matches any enabled category."""
    # Ensure category_tags are populated
    if not pkg.category_tags:
        pkg.category_tags = categorize_package(pkg)

    tags = set(pkg.category_tags)
    if include_cli and "cli" in tags:
        return True
    if include_ml and "ml" in tags:
        return True
    if include_dev and "dev" in tags:
        return True

    return False
