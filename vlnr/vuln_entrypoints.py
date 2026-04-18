import ast
import configparser
import os
import re
import tomllib
from dataclasses import dataclass
from typing import Optional


@dataclass
class EntryPoint:
    file: str
    function_name: str
    line: int
    type: str  # "cli" or "api"


def discover_entrypoints(local_path: str) -> list[EntryPoint]:
    """
    Discovers entry points from configuration files and code.
    """
    entrypoints = []

    # 1. Check pyproject.toml
    pyproject_path = os.path.join(local_path, "pyproject.toml")
    if os.path.exists(pyproject_path):
        try:
            with open(pyproject_path, "rb") as f:
                data = tomllib.load(f)
                scripts = data.get("project", {}).get("scripts", {})
                for name, spec in scripts.items():
                    ep = parse_spec(local_path, spec, "cli")
                    if ep:
                        entrypoints.append(ep)
        except Exception:
            pass

    # 2. Check setup.cfg
    setup_cfg_path = os.path.join(local_path, "setup.cfg")
    if os.path.exists(setup_cfg_path):
        try:
            config = configparser.ConfigParser()
            config.read(setup_cfg_path)
            if "options.entry_points" in config:
                for line in config["options.entry_points"].get("console_scripts", "").splitlines():
                    if "=" in line:
                        spec = line.split("=")[1].strip()
                        ep = parse_spec(local_path, spec, "cli")
                        if ep:
                            entrypoints.append(ep)
        except Exception:
            pass

    # 3. Check setup.py (regex)
    setup_py_path = os.path.join(local_path, "setup.py")
    if os.path.exists(setup_py_path):
        try:
            with open(setup_py_path, "r") as f_setup:
                content = f_setup.read()
                # Simple regex for 'console_scripts': ['name = module:func']
                matches = re.findall(r"['\"]console_scripts['\"]\s*:\s*\[([^\]]+)\]", content)
                for match in matches:
                    specs = re.findall(r"['\"]([^'\"]+)['\"]", match)
                    for spec_full in specs:
                        if "=" in spec_full:
                            spec = spec_full.split("=")[1].strip()
                            ep = parse_spec(local_path, spec, "cli")
                            if ep:
                                entrypoints.append(ep)
        except Exception:
            pass

    # 4. Discover public API (Functions in root __init__.py and root .py files)
    root_files = [f for f in os.listdir(local_path) if f.endswith(".py") or f == "__init__.py"]
    for filename in root_files:
        path_root = os.path.join(local_path, filename)
        if not os.path.isfile(path_root):
            continue
        try:
            with open(path_root, "r") as f_root:
                tree = ast.parse(f_root.read())
                for node in tree.body:
                    if isinstance(node, ast.FunctionDef) and not node.name.startswith("_"):
                        entrypoints.append(
                            EntryPoint(file=filename, function_name=node.name, line=node.lineno, type="api")
                        )
        except Exception:
            pass

    return entrypoints


def parse_spec(local_path: str, spec: str, ep_type: str) -> Optional[EntryPoint]:
    """Parses a spec like 'pkg.module:func'"""
    if ":" not in spec:
        return None
    module_path, func_name = spec.split(":")

    # Search for the file in local_path
    # Heuristic: match the tail of the path
    rel_path_tail = module_path.replace(".", os.sep) + ".py"

    for root, _, files in os.walk(local_path):
        for f in files:
            full_p = os.path.join(root, f)
            if full_p.endswith(rel_path_tail):
                try:
                    with open(full_p, "r") as f_obj:
                        tree = ast.parse(f_obj.read())
                        for node in tree.body:
                            if isinstance(node, ast.FunctionDef) and node.name == func_name:
                                return EntryPoint(
                                    file=os.path.relpath(full_p, local_path),
                                    function_name=func_name,
                                    line=node.lineno,
                                    type=ep_type,
                                )
                except Exception:
                    pass
    return None
