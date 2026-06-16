from typer.testing import CliRunner

from vlnr.__main__ import app

runner = CliRunner()


def test_root_help_lists_subcommands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "discover" in result.stdout
    assert "scan" in result.stdout
    assert "agent" in result.stdout
    assert "run" in result.stdout


def test_no_args_prints_help() -> None:
    result = runner.invoke(app, [])
    # Version-dependent: with `no_args_is_help=True` and 2+ subcommands, click 8.3.x
    # raises `NoArgsIsHelpError` (exit_code 2); older click versions exit 0. Accept both.
    assert result.exit_code in (0, 2)
    # Version-dependent: typer/click may route the no-args help to stdout or stderr
    # depending on the pinned version. Use combined output for portability.
    assert "Usage:" in (result.stdout + result.stderr)


def test_discover_help() -> None:
    result = runner.invoke(app, ["discover", "--help"])
    assert result.exit_code == 0
    assert "--osv-dump" in result.stdout


def test_scan_help() -> None:
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--llm-triage" in result.stdout


def test_agent_help() -> None:
    result = runner.invoke(app, ["agent", "--help"])
    assert result.exit_code == 0
    assert "--budget" in result.stdout


def test_discover_missing_osv_dump_exits_nonzero() -> None:
    result = runner.invoke(app, ["discover"])
    assert result.exit_code != 0
