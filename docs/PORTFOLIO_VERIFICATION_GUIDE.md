# How I'd walk you through this repo (2-minute skim)

**Repo:** `JsonCMorgan/boundry-ai-soc-platform` (see [profile README](https://github.com/JsonCMorgan/JsonCMorgan) for who I am)

**Why it exists:** If you're curious how this project fits together, this is the short path I use when someone asks "what should I click first?"

---

## Start here (about 60 seconds)

1. Open [my GitHub profile](https://github.com/JsonCMorgan) and skim **What I'm building on GitHub**.
2. Come back here: [boundry-ai-soc-platform](https://github.com/JsonCMorgan/boundry-ai-soc-platform) on `main` with **green CI**.
3. Scroll the README screenshots and the security section, then peek at [docs/SECURITY.md](SECURITY.md).
4. If you care about detections: [soc-detection-rules](https://github.com/JsonCMorgan/soc-detection-rules) MITRE table + pytest CI.

**Straight talk:** This is portfolio and home-lab work. I'm early in my cyber career and I build in public so the thinking is visible.

---

## What each pinned repo is for

| Repo | What I'm practicing | What to click |
|------|---------------------|---------------|
| boundry-ai-soc-platform | SIEM-style workflow, triage, reporting | `docs/SECURITY.md`, `.github/workflows/ci.yml`, README screenshots |
| soc-detection-rules | Sigma, Splunk/KQL conversion | `rules/`, MITRE table in README, CI |
| security-onion-lab | NSM, PCAP replay, analyst tickets | `tickets/LAB-*.md`, exercise docs |
| juice-shop-lab | AppSec + detection pairing | `detections/`, `tickets/LAB-JUICE-*.md` |

---

## Quick sanity checks

| Check | What "good" looks like |
|-------|-------------------------|
| CI | Flagship + detection-rules workflows green on `main` |
| License | MIT `LICENSE` on public code repos |
| Security contact | Root `SECURITY.md` or `docs/SECURITY.md` |
| Ethics | Tickets use synthetic IPs and lab hostnames only |
| Narrative | Profile bio and READMEs agree (SOC labs / Boundry) |

---

## If you want to run it (about 5 minutes)

1. Clone boundry → `pip install -r requirements-dev.txt` → `pytest -q` (or trust the CI logs).
2. Clone soc-detection-rules → `pytest -q` (pySigma backends).
3. Read one ticket from each lab repo and see how I write severity, evidence, and disposition.

---

## Find me

Jason Morgan · json.c.morgan@gmail.com · [LinkedIn](https://www.linkedin.com/in/jason-morgan-110656289/)

Greater Toronto Area, Canada.

---

*Full rubric and private-repo notes: `docs/GITHUB_INDUSTRY_AUDIT.md`.*