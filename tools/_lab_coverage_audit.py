"""Print Career lab scenario inventory for live-coverage audit. ASCII-only."""
from __future__ import annotations

import email_lab
import edr_lab
import entra_lab
import vuln_lab
import intel_lab
import log_lab
import net_lab
import sentinel_lab
import comms_lab
import tune_lab
import oversight_lab
import soar_career_lab
import policy_lab
import automation_lab
import metrics_lab


def _items(mod, *names):
    for n in names:
        v = getattr(mod, n, None)
        if v is not None:
            return n, v
    return None, []


LABS = [
    ("email", email_lab, ("SAMPLES", "CASES")),
    ("edr", edr_lab, ("CASES",)),
    ("entra", entra_lab, ("CASES",)),
    ("vuln", vuln_lab, ("CASES",)),
    ("intel", intel_lab, ("CASES",)),
    ("logs", log_lab, ("DRILLS", "CASES")),
    ("net", net_lab, ("DRILLS", "CASES")),
    ("sentinel", sentinel_lab, ("CASES",)),
    ("comms", comms_lab, ("SCENARIOS", "CASES")),
    ("tune", tune_lab, ("DRILLS", "SCENARIOS")),
    ("oversight", oversight_lab, ("CASES", "SCENARIOS")),
    ("soar", soar_career_lab, ("SCENARIOS", "CASES")),
    ("policy", policy_lab, ("SCENARIOS",)),
    ("automation", automation_lab, ("DRILLS", "SCENARIOS")),
    ("metrics", metrics_lab, ("QUIZ",)),
]


def main() -> None:
    for name, mod, attrs in LABS:
        attr, items = _items(mod, *attrs)
        print(f"\n=== {name} ({attr}={len(items)}) ===")
        for it in items:
            if not isinstance(it, dict):
                print(f"  - {it}")
                continue
            tid = it.get("id") or "?"
            title = it.get("title") or it.get("stem") or it.get("name") or ""
            # strip non-ascii for console
            title = title.encode("ascii", "replace").decode("ascii")
            print(f"  - {tid}: {title[:90]}")


if __name__ == "__main__":
    main()
