import ast
import logging
from typing import Literal
from vlnr.vuln_models import Slice, DataflowNode

logger = logging.getLogger(__name__)

# Sinks and their expected argument positions or names
SINKS = {
    "os.system": [0],
    "subprocess.run": [0],
    "subprocess.Popen": [0],
    "subprocess.call": [0],
    "subprocess.check_call": [0],
    "subprocess.check_output": [0],
    "eval": [0],
    "exec": [0],
    "pickle.load": [0],
    "pickle.loads": [0],
    "yaml.load": [0],
    "yaml.unsafe_load": [0],
}

SOURCES = {
    "sys.argv",
    "os.environ",
    "input",
}

def get_call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        parts = []
        curr_call: ast.AST = node.func
        while isinstance(curr_call, ast.Attribute):
            parts.append(curr_call.attr)
            curr_call = curr_call.value
        if isinstance(curr_call, ast.Name):
            parts.append(curr_call.id)
        return ".".join(reversed(parts))
    return ""

def is_source(node: ast.AST) -> bool:
    if isinstance(node, ast.Name) and node.id in SOURCES:
        return True
    if isinstance(node, ast.Attribute):
        name = ""
        curr_attr: ast.AST = node
        parts = []
        while isinstance(curr_attr, ast.Attribute):
            parts.append(curr_attr.attr)
            curr_attr = curr_attr.value
        if isinstance(curr_attr, ast.Name):
            parts.append(curr_attr.id)
            name = ".".join(reversed(parts))
        if name in SOURCES:
            return True
    if isinstance(node, ast.Subscript):
        return is_source(node.value)
    return False

def ast_taint_scan(tree: ast.AST, package: str, version: str, filename: str) -> list[Slice]:
    slices: list[Slice] = []
    
    # Simple intra-procedural scan
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            tainted_vars: dict[str, list[DataflowNode]] = {}
            # Track the original source that tainted the variable
            var_sources: dict[str, set[str]] = {}
            
            for stmt in node.body:
                # Assignments
                if isinstance(stmt, ast.Assign):
                    # Check for sanitizers
                    is_sanitized = False
                    if isinstance(stmt.value, ast.Call):
                        name = get_call_name(stmt.value)
                        if name in ["shlex.quote", "urllib.parse.quote", "html.escape"]:
                            is_sanitized = True
                    
                    if is_sanitized:
                        # Clear taint if re-assigned with sanitizer
                        for target in stmt.targets:
                            if isinstance(target, ast.Name):
                                tainted_vars.pop(target.id, None)
                                var_sources.pop(target.id, None)
                        continue

                    # Check if value is tainted
                    found_sources = set()
                    is_tainted = False
                    
                    for subnode in ast.walk(stmt.value):
                        if is_source(subnode):
                            is_tainted = True
                            found_sources.add(ast.unparse(subnode))
                        if isinstance(subnode, ast.Name) and subnode.id in tainted_vars:
                            is_tainted = True
                            found_sources.update(var_sources.get(subnode.id, set()))
                    
                    if is_tainted:
                        df_node = DataflowNode(
                            file=filename,
                            line=stmt.lineno,
                            expr=ast.unparse(stmt)
                        )
                        for target in stmt.targets:
                            if isinstance(target, ast.Name):
                                trail = tainted_vars.get(target.id, [])
                                tainted_vars[target.id] = trail + [df_node]
                                sources = var_sources.get(target.id, set())
                                var_sources[target.id] = sources | found_sources

                # Calls (Sinks)
                if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                    call_node = stmt.value
                    call_name = get_call_name(call_node)
                    if call_name in SINKS:
                        # Check args
                        tainted_sources_found = set()
                        dataflow = []
                        for arg in call_node.args:
                            for subnode in ast.walk(arg):
                                if is_source(subnode):
                                    tainted_sources_found.add(ast.unparse(subnode))
                                    dataflow.append(DataflowNode(file=filename, line=call_node.lineno, expr=ast.unparse(call_node)))
                                if isinstance(subnode, ast.Name) and subnode.id in tainted_vars:
                                    tainted_sources_found.update(var_sources.get(subnode.id, set()))
                                    dataflow.extend(tainted_vars[subnode.id])
                                    dataflow.append(DataflowNode(file=filename, line=call_node.lineno, expr=ast.unparse(call_node)))

                        if tainted_sources_found:
                            # Heuristic for obvious vs suspicious
                            static_class: Literal["obvious_vuln", "suspicious", "benign"] = "suspicious"
                            if call_name in ["os.system", "eval", "exec"]:
                                static_class = "obvious_vuln"
                            
                            # Check for shell=True in subprocess
                            for kw in call_node.keywords:
                                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                    static_class = "obvious_vuln"

                            slices.append(Slice(
                                slice_id=f"{package}-{filename}-{call_node.lineno}",
                                package=package,
                                version=version,
                                category=["Command Injection"] if "system" in call_name or "subprocess" in call_name else ["Other"],
                                sink_api=call_name,
                                static_class=static_class,
                                risk_score_static=0.8 if static_class == "obvious_vuln" else 0.5,
                                source_types=list(tainted_sources_found),
                                dataflow_summary=dataflow,
                                code_snippets=[] # To be filled by slice constructor
                            ))

    return slices
