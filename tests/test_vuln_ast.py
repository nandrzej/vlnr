import ast
from vlnr.vuln_ast import ast_taint_scan


def test_simple_command_injection() -> None:
    code = """
import os
import sys

def main():
    cmd = sys.argv[1]
    os.system(cmd)
"""
    tree = ast.parse(code)
    # We will implement ast_taint_scan to return list of Slice objects
    slices = ast_taint_scan(tree, "test-pkg", "1.0.0", "test_file.py")

    assert len(slices) == 1
    s = slices[0]
    assert s.static_class == "obvious_vuln"
    assert s.sink_api == "os.system"
    assert "sys.argv" in s.source_types
    assert any(node.expr == "cmd = sys.argv[1]" for node in s.dataflow_summary)


def test_sanitized_input() -> None:
    code = """
import os
import sys
import shlex

def main():
    cmd = shlex.quote(sys.argv[1])
    os.system(cmd)
"""
    tree = ast.parse(code)
    slices = ast_taint_scan(tree, "test-pkg", "1.0.0", "test_file.py")

    assert len(slices) == 1
    assert slices[0].static_class == "benign"


def test_complex_dataflow() -> None:
    code = """
import os
import sys
import subprocess

def process():
    a = sys.argv[1]
    b = a
    c = f"prefix_{b}"
    subprocess.run(c, shell=True)
"""
    tree = ast.parse(code)
    slices = ast_taint_scan(tree, "test-pkg", "1.0.0", "test_file.py")

    assert len(slices) == 1
    s = slices[0]
    assert s.static_class == "obvious_vuln"
    assert s.sink_api == "subprocess.run"
    assert "sys.argv" in s.source_types
