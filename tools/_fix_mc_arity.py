"""Find and report _mc/_qz calls with wrong argument counts in gen_secplus_d*.py."""
import ast
from pathlib import Path

TOOLS = Path(__file__).parent
for path in sorted(TOOLS.glob("gen_secplus_d*.py")):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name):
            continue
        name = node.func.id
        n = len(node.args)
        if name == "_mc" and n != 5:
            print(f"{path.name}:{node.lineno} _mc args={n}")
        if name == "_qz" and n != 5:
            print(f"{path.name}:{node.lineno} _qz args={n}")
