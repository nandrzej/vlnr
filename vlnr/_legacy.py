import warnings

import typer


def find_candidates_shim() -> None:
    warnings.warn(
        "`poc-find-candidates` is deprecated; use `vlnr discover` "
        "(or `vlnr agent`). This shim will be removed in a future release.",
        DeprecationWarning,
        stacklevel=2,
    )
    from vlnr.cli import app

    app()


def scan_shim() -> None:
    warnings.warn(
        "`poc-scan-vulnerabilities` is deprecated; use `vlnr scan`. This shim will be removed in a future release.",
        DeprecationWarning,
        stacklevel=2,
    )
    from vlnr.vuln_cli import scan

    typer.run(scan)
