# Boundry Unified SecOps UX

Local training surface modeled on enterprise SIEM/SOAR patterns. **Not** connected to Microsoft Sentinel, Splunk ES, IBM QRadar, or CrowdStrike.

## Vendor pattern → Boundry screen

| Enterprise pattern | Boundry route |
|--------------------|---------------|
| Defender home / SOC overview | `/control-room` + SecOps KPI strip |
| Splunk Mission Control queue | `/soc/mission` |
| SOC analyst floor / case workspace | `/soc` |
| QRadar Log Activity | `/siem` (Streaming / Grouped / Detections tabs) |
| Advanced hunting / SPL | `/siem/query` |
| SOAR incidents + playbooks | `/soar`, `/playbooks` |

## Object model (honest labels)

- **Log event** → `siem_events`
- **Detection / notable** → `system_findings` (correlation)
- **Case / ticket** → `soc_cases` (BT-…)
- **SOAR incident** → `soar_incidents`
- **Entity / observable** → `soc_lab.observables_for_ticket()`
- **Enrichment** → `soc_ioc_stub.lookup_ioc()` (offline)

## Shell

All Live ops pages share `_secops_layout.html` left rail and honesty banner.

## APIs (smoke)

```bash
pytest tests/test_enterprise_secops.py -q
```
