"""One-shot: extract D1 add() calls into gen_secplus_d1.py."""
from pathlib import Path

src = Path(__file__).with_name("gen_secplus_phase1.py").read_text(encoding="utf-8")
start = src.index('add(\n    "sp_d1_01')
end = src.index('print(f"D1 lessons')
chunk = src[start:end]
lines = chunk.splitlines()
indented = [("    " + line) if line.strip() else "" for line in lines]
out = (
    '"""D1 lesson specs for Phase 1 builder."""\n'
    "from __future__ import annotations\n\n\n"
    "def d1_specs(add, _mc, _qz):\n"
    '    """Register Domain 1 micro-lessons (6)."""\n\n'
    + "\n".join(indented)
    + "\n"
)
Path(__file__).with_name("gen_secplus_d1.py").write_text(out, encoding="utf-8")
print("wrote gen_secplus_d1.py", len(out))
