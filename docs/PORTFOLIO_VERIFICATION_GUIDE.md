# Portfolio verification guide (2-page skim)

**Audience:** Hiring managers and technical screeners reviewing **Jason Morgan** (`JsonCMorgan`).

**Purpose:** Verify junior SOC readiness in under two minutes without reading the full internal audit.

---

## Start here (60 seconds)

1. Open [github.com/JsonCMorgan](https://github.com/JsonCMorgan) profile README.
2. Skim the **What to look at first** table (four cyber repos).
3. Open [boundry-ai-soc-platform](https://github.com/JsonCMorgan/boundry-ai-soc-platform) → confirm green **CI** badge and read the first screen of `README.md`.
4. Optional depth: [soc-detection-rules](https://github.com/JsonCMorgan/soc-detection-rules) MITRE table + passing pytest CI.

**Honest framing:** These are **portfolio and home-lab builds**, not a commercial MSSP contract or multi-year employer SOC tenure.

---

## What each pinned repo proves

| Repo | Skill signal | Evidence to click |
|------|--------------|-------------------|
| boundry-ai-soc-platform | SIEM-style workflow, triage, reporting, SSDF hygiene | `docs/SECURITY.md`, `.github/workflows/ci.yml`, Control Room screenshots in README |
| soc-detection-rules | Detection engineering, Sigma, Splunk/KQL conversion | `rules/`, MITRE table in README, CI pytest |
| security-onion-lab | NSM, PCAP replay, analyst tickets | `tickets/LAB-*.md`, exercise docs |
| juice-shop-lab | AppSec + detection pairing | `detections/`, `tickets/LAB-JUICE-*.md` |

---

## Verification checklist (recruiter or peer)

| Step | Pass criteria |
|------|----------------|
| CI | Flagship + detection-rules workflows green on `main` |
| License | MIT `LICENSE` on public code repos |
| Security contact | Root `SECURITY.md` or `docs/SECURITY.md` |
| Ethics | Tickets use synthetic IPs and lab hostnames only |
| Narrative | Profile bio matches README (SOC / Boundry, not unrelated trade) |

---

## Technical reviewer (5 minutes)

1. Clone boundry → `pip install -r requirements-dev.txt` → `pytest -q` (or trust CI logs).
2. Clone soc-detection-rules → `pytest -q` (validates pySigma backends).
3. Read one ticket from each lab repo and confirm disposition language (severity, evidence, decision).

---

## Contact

Jason Morgan · json.c.morgan@gmail.com · [LinkedIn](https://www.linkedin.com/in/jason-morgan-110656289/)

Greater Toronto Area, Canada. Open to junior SOC and security operations analyst roles.

---

*Derived from `docs/GITHUB_INDUSTRY_AUDIT.md`. Full rubric and private-repo notes stay in-repo for Boundry ops.*