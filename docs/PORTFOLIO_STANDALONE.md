# Standalone portfolio repos (not the MSSP monolith)

**Purpose:** Repos a recruiter can open in 90 seconds. Each = one story. **Do not merge into `boundry-ai-soc-platform`** except optional thin integration (import package or API).

**Flagship:** [boundry-ai-soc-platform](https://github.com/JsonCMorgan/boundry-ai-soc-platform) stays the “operator platform” proof. Everything below is **extra repos on the shelf**.

---

## Shipped (show these now)

| # | Repo | Local path | 30-second pitch | MSSP tie-in |
|---|------|------------|-----------------|-------------|
| 2 | [security-onion-lab](https://github.com/JsonCMorgan/security-onion-lab) | `C:\Dev\security-onion-lab` | PCAP → Suricata/Zeek → short IR note | None |
| 3 | [juice-shop-lab](https://github.com/JsonCMorgan/juice-shop-lab) | `C:\Dev\juice-shop-lab` | OWASP attacks with **defender** detection angle | None |
| 4 | [phishing-email-analyzer](https://github.com/JsonCMorgan/phishing-email-analyzer) | `C:\Dev\phishing-email-analyzer` | `.eml` → SPF/DKIM/DMARC + defanged URLs | Logic forked from `email_lab`; MSSP keeps training UI only |
| 7 | [soc-detection-rules](https://github.com/JsonCMorgan/soc-detection-rules) | `C:\Dev\soc-detection-rules` | Sigma → Splunk/KQL in CI | Boundry can *consume* rules; repo stays separate |
| — | [link-check](https://github.com/JsonCMorgan/link-check) *(public product)* | `C:\Dev\link-check` | Pre-click link/QR triage for hiring smish | Optional `/ops/link-check`; **5055 app is the pitch** |
| 5 | [ioc-extractor](https://github.com/JsonCMorgan/ioc-extractor) | `C:\Dev\ioc-extractor` | Paste report → IOC JSON/CSV; opt-in enrich | MSSP **6b** = on-demand enrich in SIEM; **not** this package |

---

## Tier B — build next (one repo each, recruiter food)

| # | Tool | Repo name (suggested) | Why standalone | Priority |
|---|------|----------------------|----------------|----------|
| 6 | Windows Event Log Hunter | `windows-evtx-hunter` | Classic “read the EVTX” interview skill; HTML timeline | **High** — pairs with G8 |
| 8 | Linux auth.log analyzer | `linux-authlog-analyzer` | SSH brute / sudo / persistence | High — closes G10 gap |
| 9 | PCAP triage | `pcap-triage` | Beaconing + DNS noise; pairs with Security Onion lab | Medium |
| 10 | Breached password checker | `hibp-password-check` | HIBP k-anonymity privacy story | Medium (fast build) |
| 11 | Network asset change detector | `network-asset-diff` | nmap diff over time; **do not** port whole `system_scanner` | Lower (overlap with flagship) |

**Rule:** CLI + README screenshot + pytest + GitHub Actions badge. No Flask dashboard unless it’s a tiny public app like Link Check.

---

## Tier C — labs (separate repos or folders under one `blue-team-labs` mono-repo)

| # | Lab | Format | Notes |
|---|-----|--------|-------|
| 12 | AD attack-and-defend | Own repo or `ad-lab` | Heavy VM work; writeups + detection rules |
| 13 | Wazuh vs Boundry compare | Doc in repo or `wazuh-lab` | “Built both” story — **comparison**, not merge |
| 14 | Splunk Free + BOTS | `splunk-bots-lab` | Activates your forwarder story without stuffing MSSP |
| 15 | Blue Team writeups | `blue-team-writeups` | CyberDefenders / LetsDefend — low code, high signal |

Use **one repo per lab** if you want maximum GitHub tile count; use **`blue-team-writeups`** if you want one place for markdown-only evidence.

---

## Keep inside MSSP (do not spin out)

| Roadmap | Why |
|---------|-----|
| Tier A **#1** hygiene on flagship | One SOC platform narrative |
| Tier D **#16–19** (reviewer mode, Navigator, LLM bench, interview export) | Product features, not tools |
| Stage **6b** SIEM enrich button | Operator workflow on Live SIEM |
| Career Hub, Sec+, Interview Gym, `/soc` | Training product surface |

---

## Suggested build order (recruiter shelf, not scale)

1. **Push / verify #5** `ioc-extractor` if not on GitHub yet  
2. **#6** EVTX Hunter — strongest junior SOC differentiator  
3. **#8** Linux auth — shows breadth beyond Windows  
4. **Link Check** — deploy demo URL when ready; already strongest non-SOC story  
5. **#10** HIBP — quick win between heavy builds  
6. **#9** PCAP — link from `security-onion-lab` README  

After **4–6 standalone tools + 2 labs + flagship**, profile stops looking like “one huge repo.”

---

## Profile README (when updating JsonCMorgan)

Add rows for `link-check`, `ioc-extractor`, `phishing-email-analyzer` ahead of or beside the flagship table. Cap at **5–7** “look here first” links.

Source roadmap: agent plan `security_portfolio_roadmap` + Stage 6 in `docs/IMPLEMENTATION_PLAN.md`.