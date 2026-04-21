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
    "open": [0],
    "os.remove": [0],
    "os.rename": [0, 1],
    "shutil.rmtree": [0],
}

BYPASS_SINKS = {
    "os.system",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "urllib.request.urlopen",
    "requests.get",
    "requests.post",
    "requests.request",
    "eval",
    "exec",
    "base64.b64decode",
    "base64.decodestring",
    "marshal.loads",
    "builtins.exec",
    "builtins.eval",
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

            sanitized_vars: set[str] = set()

            for stmt in node.body:
                # Assignments
                if isinstance(stmt, ast.Assign):
                    # Check for sanitizers
                    is_sanitized = False
                    if isinstance(stmt.value, ast.Call):
                        name = get_call_name(stmt.value)
                        if name in ["shlex.quote", "urllib.parse.quote", "html.escape"]:
                            is_sanitized = True

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
                        df_node = DataflowNode(file=filename, line=stmt.lineno, expr=ast.unparse(stmt))
                        for target in stmt.targets:
                            if isinstance(target, ast.Name):
                                trail = tainted_vars.get(target.id, [])
                                tainted_vars[target.id] = trail + [df_node]
                                sources = var_sources.get(target.id, set())
                                var_sources[target.id] = sources | found_sources
                                if is_sanitized:
                                    sanitized_vars.add(target.id)
                                else:
                                    sanitized_vars.discard(target.id)
                    else:
                        for target in stmt.targets:
                            if isinstance(target, ast.Name):
                                tainted_vars.pop(target.id, None)
                                var_sources.pop(target.id, None)
                                sanitized_vars.discard(target.id)

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
                                    dataflow.append(
                                        DataflowNode(file=filename, line=call_node.lineno, expr=ast.unparse(call_node))
                                    )
                                if isinstance(subnode, ast.Name) and subnode.id in tainted_vars:
                                    tainted_sources_found.update(var_sources.get(subnode.id, set()))
                                    dataflow.extend(tainted_vars[subnode.id])
                                    dataflow.append(
                                        DataflowNode(file=filename, line=call_node.lineno, expr=ast.unparse(call_node))
                                    )

                        if tainted_sources_found:
                            is_sink_sanitized = False
                            for arg in call_node.args:
                                if isinstance(arg, ast.Call) and get_call_name(arg) in [
                                    "shlex.quote",
                                    "urllib.parse.quote",
                                    "html.escape",
                                ]:
                                    is_sink_sanitized = True
                                for subnode in ast.walk(arg):
                                    if isinstance(subnode, ast.Name) and subnode.id in sanitized_vars:
                                        is_sink_sanitized = True

                            # Heuristic for obvious vs suspicious
                            static_class: Literal["obvious_vuln", "suspicious", "benign"] = "suspicious"
                            if is_sink_sanitized:
                                static_class = "benign"
                            elif call_name in [
                                "os.system",
                                "eval",
                                "exec",
                                "pickle.load",
                                "pickle.loads",
                                "yaml.load",
                                "yaml.unsafe_load",
                            ]:
                                static_class = "obvious_vuln"

                            # Check for shell=True in subprocess
                            if not is_sink_sanitized:
                                for kw in call_node.keywords:
                                    if (
                                        kw.arg == "shell"
                                        and isinstance(kw.value, ast.Constant)
                                        and kw.value.value is True
                                    ):
                                        static_class = "obvious_vuln"

                            category = ["Other"]
                            if "system" in call_name or "subprocess" in call_name:
                                category = ["Command Injection"]
                            elif call_name in [
                                "pickle.load",
                                "pickle.loads",
                                "yaml.load",
                                "yaml.unsafe_load",
                                "eval",
                                "exec",
                            ]:
                                category = (
                                    ["Deserialization"]
                                    if "yaml" in call_name or "pickle" in call_name
                                    else ["Code Execution"]
                                )
                            elif call_name in ["open", "os.remove", "os.rename", "shutil.rmtree"]:
                                category = ["Path Traversal"]

                            slices.append(
                                Slice(
                                    slice_id=f"{package}-{filename}-{call_node.lineno}",
                                    package=package,
                                    version=version,
                                    category=category,
                                    sink_api=call_name,
                                    static_class=static_class,
                                    risk_score_static=0.1
                                    if static_class == "benign"
                                    else (0.8 if static_class == "obvious_vuln" else 0.5),
                                    source_types=list(tainted_sources_found),
                                    dataflow_summary=dataflow,
                                    code_snippets=[],  # To be filled by slice constructor
                                )
                            )

    return slices


def ast_bypass_scan(tree: ast.AST, package: str, version: str, filename: str) -> list[Slice]:
    """Detects execution of suspicious sinks at the module level or inside top-level control flow."""
    slices: list[Slice] = []

    # Walk the tree but skip function and class definitions to find top-level execution
    def walk_top_level(node: ast.AST) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return

        if isinstance(node, ast.Call):
            call_name = get_call_name(node)
            if call_name in BYPASS_SINKS:
                category = ["top-level", "Bypass Signal"]
                if "requests" in call_name or "urllib" in call_name:
                    category.append("Outbound Connection")

                slices.append(
                    Slice(
                        slice_id=f"bypass-{package}-{filename}-{node.lineno}",
                        package=package,
                        version=version,
                        category=category,
                        sink_api=call_name,
                        static_class="obvious_vuln"
                        if "system" in call_name
                        or "subprocess" in call_name
                        or call_name in ["eval", "exec", "builtins.eval", "builtins.exec"]
                        else "suspicious",
                        risk_score_static=0.9 if "system" in call_name or "subprocess" in call_name else 0.7,
                        dataflow_summary=[DataflowNode(file=filename, line=node.lineno, expr=ast.unparse(node))],
                        code_snippets=[],
                    )
                )

        for child in ast.iter_child_nodes(node):
            walk_top_level(child)

    walk_top_level(tree)
    return slices
