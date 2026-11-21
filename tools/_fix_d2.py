"""Rewrite gen_secplus_d2.py to d2_specs(add, _mc, _qz) signature → gen_secplus_d2b.py."""
from pathlib import Path

src = Path(__file__).with_name("gen_secplus_d2.py").read_text(encoding="utf-8")
# Remove bad import and change signature
src = src.replace(
    'from gen_secplus_phase1 import _mc, _qz, _wrap  # type: ignore  # noqa — loaded via exec\n\n\n'
    "def d2_specs(add):\n"
    '    """Register Domain 2 micro-lessons (11) onto add()."""\n',
    "def d2_specs(add, _mc, _qz):\n"
    '    """Register Domain 2 micro-lessons (11)."""\n',
)
# Also remove unused _wrap if present
src = src.replace("from __future__ import annotations\n\nfrom gen_secplus_phase1", "from __future__ import annotations\n\n# fixed\nfrom gen_secplus_phase1")
# Simpler: rewrite header entirely
body_start = src.index("def d2_specs")
# find the function body after docstring
rest = src[body_start:]
# Ensure signature
if "def d2_specs(add):" in rest:
    rest = rest.replace("def d2_specs(add):", "def d2_specs(add, _mc, _qz):", 1)
out = (
    '"""D2 lesson specs for Phase 1 builder."""\n'
    "from __future__ import annotations\n\n\n"
    + rest
)
Path(__file__).with_name("gen_secplus_d2b.py").write_text(out, encoding="utf-8")
print("wrote gen_secplus_d2b.py", len(out))
