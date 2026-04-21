import ast
from vlnr.vuln_ast import ast_taint_scan, ast_bypass_scan

def test_init_py_top_level_execution() -> None:
    code = """
import os
os.system("whoami")
"""
    tree = ast.parse(code)
    # ast_bypass_scan is the new function to be implemented
    slices = ast_bypass_scan(tree, "test-pkg", "1.0.0", "test_pkg/__init__.py")
    
    assert len(slices) == 1
    s = slices[0]
    assert s.sink_api == "os.system"
    assert s.static_class == "obvious_vuln"
    assert "top-level" in s.category

def test_tests_dir_top_level_execution() -> None:
    code = """
import subprocess
subprocess.run(["echo", "hello"])
"""
    tree = ast.parse(code)
    slices = ast_bypass_scan(tree, "test-pkg", "1.0.0", "tests/conftest.py")
    
    assert len(slices) == 1
    s = slices[0]
    assert s.sink_api == "subprocess.run"
    assert "top-level" in s.category

def test_conjunctive_signal_escalation() -> None:
    # This might be tested via vuln_cli or a higher-level logic, 
    # but let's see if we can trigger it via ast_bypass_scan or similar.
    # The plan says: Implement logic to require >=2 co-occurring signals 
    # before escalating to PoC_Exploitable in vlnr/vuln_cli.py.
    
    # For now, let's test if ast_bypass_scan flags them as signals.
    code = """
import base64
payload = base64.b64decode("Y2FsYw==")
exec(payload)
"""
    tree = ast.parse(code)
    slices = ast_bypass_scan(tree, "test-pkg", "1.0.0", "malicious.py")
    
    # Should find at least one signal. 
    # If we implement it to find "base64 + exec" as a conjunctive signal:
    assert len(slices) >= 1
    # Check if we have both signals recorded or a combined one
    sink_apis = [s.sink_api for s in slices]
    assert "exec" in sink_apis
    # Potentially we want to see if it's marked as suspicious for escalation
    assert any(s.static_class in ["obvious_vuln", "suspicious"] for s in slices)

def test_yaml_safe_load_is_ignored() -> None:
    code = """
import yaml
yaml.safe_load("foo: bar")
"""
    tree = ast.parse(code)
    # Check both scans
    slices_taint = ast_taint_scan(tree, "test-pkg", "1.0.0", "safe.py")
    slices_bypass = ast_bypass_scan(tree, "test-pkg", "1.0.0", "safe.py")
    
    assert len(slices_taint) == 0
    assert len(slices_bypass) == 0

def test_normal_function_call_not_flagged_as_bypass() -> None:
    code = """
import os
def run():
    os.system("ls")
"""
    tree = ast.parse(code)
    slices = ast_bypass_scan(tree, "test-pkg", "1.0.0", "normal.py")
    assert len(slices) == 0
