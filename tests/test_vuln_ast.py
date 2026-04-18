import ast
import pytest
from vlnr.vuln_ast import ast_taint_scan

def test_simple_command_injection():
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

def test_sanitized_input():
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
    
    # Should be benign or no slice at all if we ignore benigns
    assert all(s.static_class == "benign" for s in slices)
