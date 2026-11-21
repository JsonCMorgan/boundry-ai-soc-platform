"""Dump Career lab scenario inventories (UTF-8)."""
from __future__ import annotations

from pathlib import Path

import automation_lab
import edr_lab
import email_lab
import entra_lab
import intel_lab
import log_lab
import net_lab
import oversight_lab
import policy_lab
import sentinel_lab
import soar_career_lab
import tune_lab
import vuln_lab

pairs = [
    ("email", email_lab.SAMPLES),
    ("edr", edr_lab.CASES),
    ("entra", entra_lab.CASES),
    ("vuln", vuln_lab.CASES),
    ("intel", intel_lab.CASES),
    ("logs", log_lab.DRILLS),
    ("net", net_lab.DRILLS),
    ("oversight", oversight_lab.CASES),
    ("tune", tune_lab.DRILLS),
    ("soar", soar_career_lab.SCENARIOS),
    ("policy", policy_lab.SCENARIOS),
    ("automation", automation_lab.DRILLS),
    ("sentinel", sentinel_lab.CASES),
]
lines: list[str] = []
for name, items in pairs:
    lines.append(f"=== {name} {len(items)}")
    for x in items:
        t = (x.get("title") or x.get("name") or "").replace("\u2192", "->")
        lines.append(f"{x.get('id')} - {t[:90]}")
out = Path(__file__).with_name("_lab_inventory.txt")
out.write_text("\n".join(lines), encoding="utf-8")
print(f"wrote {out} ({len(lines)} lines)")
