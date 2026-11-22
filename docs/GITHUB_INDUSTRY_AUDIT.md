# GitHub industry standards audit — JsonCMorgan

| Field | Value |
|-------|-------|
| Account | [JsonCMorgan](https://github.com/JsonCMorgan) |
| Audit date | 2026-11-22 (initial) |
| Last updated | 2026-11-22 (post voice, pins, push, secondary-repo banners) |
| Local flagship | `C:\Dev\MSSP` → [boundry-ai-soc-platform](https://github.com/JsonCMorgan/boundry-ai-soc-platform) |
| Overall maturity (weighted) | **3.5 / 5.0** on GitHub as of last update |
| Next re-audit | See `docs/GITHUB_AUDIT_QUARTERLY_CHECKLIST.md` |

---

## Executive summary

Public GitHub now presents a **single cyber story**: profile README in first-person voice (intro only on profile), four pinned repos, flagship + labs with LICENSE, SECURITY.md, CI, tickets, and first-person READMEs without repeated "I'm Jason" intros.

Remaining gaps vs industry-style portfolios: **redacted screenshots** in lab `screenshots/`, optional **branch protection** on flagship `main`, Dependabot PR hygiene, and evidence depth (G# map in flagship README).

**Top 10 fixes:**

| ID | Fix | Severity | Status |
|----|-----|----------|--------|
| F-001 | Align GitHub bio/location/hireable with profile README | High | **Done** (API, SOC voice) |
| F-002 | MIT LICENSE + SECURITY.md on public code repos | High | **Done** |
| F-003 | Fix soc-detection-rules CI (pySigma M365 pin) | High | **Done** (green on `main`) |
| F-004 | Repo topics + descriptions on cyber repos | Medium | **Done** |
| F-005 | Lab `tickets/` + `screenshots/` contract | Medium | **Done** (PNGs still optional) |
| F-006 | MITRE table in detection-rules README | Medium | **Done** |
| F-007 | Dependabot on boundry + detection-rules | Medium | **Done** |
| F-008 | CI on NSM / Juice labs | Low | **Done** |
| F-009 | Pin 4 cyber repos on profile | Medium | **Done** (UI) |
| F-010 | Drift Tamers noise on profile | Low | **Done** (issues disabled; cafe-quiz on profile) |
| F-011 | Secondary repos: banner + description | Low | **Done** (`job-app-copilot`, `boundry.ai`, `peta-tools-web`) |
| F-012 | Remove hiring-manager framing; profile owns identity | Medium | **Done** (README voice pass) |

**Deep dive for reviewers:** `docs/PORTFOLIO_VERIFICATION_GUIDE.md` (optional PDF for applications).

**Roadmap:** [Remediation roadmap](#remediation-roadmap-30-60-90-days).

---

## Scope and methodology

**In scope:** 8 public repos, 4 private Boundry-related repos, local drift for `C:\Dev\MSSP`.

**Frameworks:**

| Framework | Use in this audit |
|-----------|-------------------|
| NIST SP 800-218 (SSDF) | PO/PS/PW/RV mapped to LICENSE, CI, SECURITY.md, response |
| OpenSSF Best Practices | LICENSE, SECURITY.md, CI, dependency updates |
| SOC portfolio anatomy | tickets/, rules/, docs/, sanitization |
| Sigma / MITRE | rule tags, CI conversion tests |
| CIS Controls v8 (doc only) | 6, 8, 16 as documentation patterns |

**Method:** `gh` API inventory, workflow run history, root tree listing, local git drift, pytest on detection-rules, manual rubric scoring.

**Voice rule (2026-11-22):** Profile README introduces identity; child repo READMEs use first person without repeating name intro.

---

## Weighted rubric (1–5)

| # | Category | Weight | Pre (Nov AM) | Current | Framework |
|---|----------|--------|--------------|---------|-----------|
| 1 | Narrative and discoverability | 15% | 2 | **4** | Profile, pins, banners, bio |
| 2 | Documentation quality | 15% | 4 | **4** | README, SECURITY.md |
| 3 | SSDF / OpenSSF hygiene | 20% | 3 | **4** | CI, LICENSE, Dependabot |
| 4 | SOC operational artifacts | 15% | 2 | **3** | tickets; screenshots thin |
| 5 | Detection engineering | 15% | 4 | **4** | Sigma, MITRE, CI |
| 6 | AppSec / IR | 10% | 3 | **3** | Juice Shop, templates |
| 7 | Ethics and privacy | 5% | 4 | **4** | Sanitized lab data |
| 8 | Activity and maintainability | 5% | 3 | **3** | Green CI; stale repos labeled |

**Weighted overall:** Pre **2.6** → Current **3.5**.

---

## Account-level findings

### ACC-001 — Bio contradicts README

| | |
|---|---|
| Severity | High |
| Status | **Resolved** |
| Evidence | Bio now SOC / Boundry / learning in public |
| Remediation | Applied via `gh api PATCH user` |

### ACC-002 — Pins not set to cyber story

| | |
|---|---|
| Severity | Medium |
| Status | **Resolved** |
| Evidence | GraphQL `pinnedItems`: boundry-ai-soc-platform, soc-detection-rules, security-onion-lab, juice-shop-lab |

### ACC-003 — Drift Tamers / game noise

| | |
|---|---|
| Severity | Low |
| Status | **Mitigated** |
| Evidence | Issues disabled on profile repo; `cafe-quiz/` on profile for drills |

### ACC-004 — Secondary public repos dilute brand

| | |
|---|---|
| Severity | Low |
| Status | **Resolved** |
| Evidence | README banner + `gh repo edit` descriptions on `job-app-copilot`, `boundry.ai`, `peta-tools-web` |
| Note | Repos left **unarchived** so links still work; banners route visitors to pins |

---

## Per-repo scorecards (public)

### boundry-ai-soc-platform — **4 / 5**

CI green (gitleaks, ruff, pytest); LICENSE, SECURITY.md, Dependabot; first-person README; showcase screenshots in README.

### soc-detection-rules — **4 / 5**

12 rules, MITRE table, pytest CI green on `main`.

### security-onion-lab — **3.5 / 5**

Docs, tickets, CI structure job; needs real screenshots.

### juice-shop-lab — **3.5 / 5**

Same as onion lab.

### JsonCMorgan (profile) — **4.5 / 5**

First-person voice, repo table, cafe-quiz, pins aligned.

### job-app-copilot — **2 / 5** (labeled secondary)

Portfolio banner; job-hunt tooling; not pinned.

### boundry.ai — **2 / 5** (labeled secondary)

Business assets; banner points to pins.

### peta-tools-web — **2 / 5** (labeled secondary)

New README + banner; `master` branch (legacy).

---

## Private repo pass (summary)

| Repo | Classification |
|------|----------------|
| boundry-mcp-server | Private; public stub deferred |
| geo-audit-tool | Never public |
| peta-tools | Never public |
| jason-job-agent | Never public |

See `docs/LLM_MCP_SECURITY.md`.

---

## Local / remote drift register

| Path | Remote | Status (2026-11-22 PM) |
|------|--------|------------------------|
| C:\Dev\MSSP | boundry-ai-soc-platform | In sync after audit doc push |
| C:\Dev\soc-detection-rules | soc-detection-rules | In sync |
| C:\Dev\security-onion-lab | security-onion-lab | In sync |
| C:\Dev\juice-shop-lab | juice-shop-lab | In sync |
| C:\Users\ricka\Documents\JsonCMorgan | JsonCMorgan | In sync |
| C:\Dev\job-app-copilot | job-app-copilot | In sync (banner) |
| C:\Dev\boundry.ai | boundry.ai | In sync (banner) |
| C:\Dev\peta-tools-web | peta-tools-web | In sync (new README) |

---

## CI status snapshot (2026-11-22 PM)

| Repo | Latest `main` / `master` CI | Result |
|------|---------------------------|--------|
| boundry-ai-soc-platform | CI | **success** |
| soc-detection-rules | CI | **success** |
| security-onion-lab | CI structure | **success** |
| juice-shop-lab | CI structure | **success** |
| JsonCMorgan | Pages | **success** |

---

## Branch protection (documented, not applied)

On `boundry-ai-soc-platform` **main**: require status checks (`Secrets scan`, `Lint`, `Tests`). Optional until solo workflow feels stable.

Track in `docs/PRE_CLIENT_HARDENING.md`.

---

## Remediation roadmap (30 / 60 / 90 days)

### Days 0–30 (credibility) — **complete**

- Pushed cyber repos and profile.
- Metadata, pins, CI green, voice pass, secondary banners.

### Days 31–60 (evidence) — **in progress**

- [ ] One redacted screenshot per lab.
- [ ] Link G# skills in flagship README (`docs/soc-l1-skills-roadmap.md`).
- [ ] Merge or close stale Dependabot PRs on `soc-detection-rules`.

### Days 61–90 (advanced)

- [ ] Optional CodeQL on flagship Python.
- [ ] MCP public stub or written deferral.
- [ ] PDF export of portfolio walkthrough for applications.

---

## Framework mapping appendix

| SSDF practice | JsonCMorgan evidence |
|---------------|----------------------|
| PO.1 | README problem statements |
| PS.1 | gitleaks CI, `.gitleaksignore` |
| PW.5 | pytest regression |
| RV.1 | SECURITY.md reporting |

---

## Ongoing governance

Monthly: `docs/GITHUB_AUDIT_QUARTERLY_CHECKLIST.md`.

---

*Private-repo rows stay in this file only. Do not paste into public profile README.*