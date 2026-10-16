"""Smoke: SIEM Phase A FP modules (no Flask required)."""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import siem_fp_templates
import siem_ingest_tunes


def main() -> int:
    sev, etype, corr = siem_ingest_tunes.classify_firewall_drop("1.2.3.4", "10.0.0.1", "8080")
    assert sev == "INFO" and etype == "firewall_block_background" and not corr
    tune = siem_ingest_tunes.tune_windows_event(
        7045, "Service Name: NEPabc Service File Name: NordVPN"
    )
    assert tune and tune.correlate is False
    assert "internet_port_scan" in siem_fp_templates.TEMPLATE_IDS
    print("SMOKE_SIEM_FP_PHASE_A_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
