# Run all checks
check:
    uv run ruff check --fix .
    uv run mypy .
    PYTHONPATH=. uv run pytest