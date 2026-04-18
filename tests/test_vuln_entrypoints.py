import os
import tempfile

from vlnr.vuln_entrypoints import discover_entrypoints


def test_discover_pyproject_toml() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        os.makedirs(os.path.join(tmpdir, "my_pkg"))
        with open(os.path.join(tmpdir, "my_pkg", "cli.py"), "w") as f:
            f.write("def main(): pass\n")

        with open(os.path.join(tmpdir, "pyproject.toml"), "w") as f:
            f.write("""
[project.scripts]
my-cli = "my_pkg.cli:main"
""")
        eps = discover_entrypoints(tmpdir)
        assert len(eps) == 1
        assert eps[0].function_name == "main"
        assert "cli.py" in eps[0].file


def test_discover_setup_cfg() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        os.makedirs(os.path.join(tmpdir, "my_pkg"))
        with open(os.path.join(tmpdir, "my_pkg", "cli.py"), "w") as f:
            f.write("def main(): pass\n")

        with open(os.path.join(tmpdir, "setup.cfg"), "w") as f:
            f.write("""
[options.entry_points]
console_scripts =
    my-cli = my_pkg.cli:main
""")
        eps = discover_entrypoints(tmpdir)
        assert len(eps) == 1
        assert eps[0].function_name == "main"
