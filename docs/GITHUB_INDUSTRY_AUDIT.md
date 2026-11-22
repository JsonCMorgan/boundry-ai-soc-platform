# GitHub industry standards audit — JsonCMorgan

| Field | Value |
|-------|-------|
| Account | [JsonCMorgan](https://github.com/JsonCMorgan) |
| Audit date | 2026-11-22 |
| Local flagship | `C:\Dev\MSSP` → `boundry-ai-soc-platform` |
| Overall maturity (weighted) | **3.2 / 5.0** (post-remediation local; **2.6 / 5.0** pre-remediation on GitHub remote) |
| Next re-audit | See `docs/GITHUB_AUDIT_QUARTERLY_CHECKLIST.md` |

---

## Executive summary

Jason Morgan's public footprint already shows **credible junior SOC portfolio depth** (Boundry SIEM lab, Security Onion NSM, Juice Shop AppSec, Sigma detection pack). Industry reviewers docked points for **account bio drift** (data analyst vs SOC), **missing SPDX licenses** on public code repos, **one red CI** on `soc-detection-rules` (bad pip pin), thin **ticket/screenshot** evidence in labs, and **no Dependabot** on Python repos.

**Top 10 fixes (status as of this audit run):**

| ID | Fix | Severity | Status |
|----|-----|----------|--------|
| F-001 | Align GitHub bio/location/hireable with profile README | High | API patch prepared / applied locally in run |
| F-002 | MIT LICENSE + SECURITY.md on all public code repos | High | **Done** locally |
| F-003 | Fix soc-detection-rules CI (`pysigma-backend-microsoft365defender` pin) | High | **Done** locally; **push required** |
| F-004 | Add repo topics + descriptions on GitHub | Medium | `gh repo edit` prepared; **push + metadata** |
| F-005 | Lab `tickets/` + `screenshots/` contract | Medium | **Done** locally |
| F-006 | MITRE table in detection-rules README | Medium | **Done** locally |
| F-007 | Dependabot on boundry + detection-rules | Medium | **Done** locally |
| F-008 | CI on NSM / Juice labs | Low | **Done** locally |
| F-009 | Pin 4 cyber repos on profile | Medium | **Manual** GitHub UI only |
| F-010 | Close/migrate Drift Tamers noise on profile | Low | Issues **disabled** on profile repo; use separate game repo issues |

**Hiring manager path:** `docs/PORTFOLIO_VERIFICATION_GUIDE.md` (2-page skim). Attach PDF export when a HM requests depth.

**30 / 60 / 90 roadmap:** See [Remediation roadmap](#remediation-roadmap-30-60-90-days).

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

---

## Weighted rubric (1–5)

| # | Category | Weight | Pre | Post (local) | Framework |
|---|----------|--------|-----|--------------|-----------|
| 1 | Narrative and discoverability | 15% | 2 | 3 | Portfolio guidance, GitHub profile |
| 2 | Documentation quality | 15% | 4 | 4 | README, SECURITY.md, ADRs |
| 3 | SSDF / OpenSSF hygiene | 20% | 3 | 4 | SSDF, OpenSSF |
| 4 | SOC operational artifacts | 15% | 2 | 3 | soc-portfolio pattern |
| 5 | Detection engineering | 15% | 4 | 4 | Sigma, MITRE |
| 6 | AppSec / IR | 10% | 3 | 3 | OWASP, incident template |
| 7 | Ethics and privacy | 5% | 4 | 4 | Sanitized lab data |
| 8 | Activity and maintainability | 5% | 3 | 3 | CI green, stale repos |

**Weighted overall:** Pre **2.6**, Post **3.2** (remote still **2.6** until push).

---

## Finding format

Each finding: **ID**, severity, framework, evidence, remediation, owner, effort.

---

## Account-level findings

### ACC-001 — Bio contradicts README

| | |
|---|---|
| Severity | High |
| Framework | Portfolio discoverability |
| Evidence | Bio: "data analyst"; README: junior SOC |
| Remediation | PATCH user bio, location `Greater Toronto Area, Canada`, company `Boundry.AI`, `hireable: true` |
| Owner | Jason | Effort | S |

### ACC-002 — Pins not set to cyber story

| | |
|---|---|
| Severity | Medium |
| Framework | Narrative |
| Evidence | GitHub UI pins (not API-enumerable in audit) |
| Remediation | Pin: boundry-ai-soc-platform, soc-detection-rules, security-onion-lab, juice-shop-lab |
| Owner | Jason | Effort | S (manual UI) |

### ACC-003 — Drift Tamers / game noise

| | |
|---|---|
| Severity | Low |
| Framework | Brand hygiene |
| Evidence | `gh issue list` on profile repo: **issues disabled** |
| Remediation | Keep games in `cafe-quiz/` or separate repo; do not re-enable issues on profile without cleanup plan |
| Owner | Jason | Effort | S |

### ACC-004 — Secondary public repos dilute brand

| | |
|---|---|
| Severity | Low |
| Framework | Narrative |
| Evidence | `job-app-copilot`, `boundry.ai`, `peta-tools-web` (no root README on peta-tools-web) |
| Remediation | Archive or README banner "not primary portfolio" |
| Owner | Jason | Effort | M |

---

## Per-repo scorecards (public)

### boundry-ai-soc-platform

| Score | 4 / 5 |
|-------|-------|
| Strengths | gitleaks + ruff + pytest CI green; `docs/SECURITY.md`; rich README |
| Gaps (pre-run) | No LICENSE; no topics; no Dependabot |
| Gaps (post local) | LICENSE, SECURITY.md root, dependabot added |
| CI | Last run **success** 2026-11-21 |
| Local drift | **None** (`origin/main..HEAD` empty as of 2026-11-22) |

### soc-detection-rules

| Score | 3.5 → 4 / 5 after CI fix |
|-------|---------------------------|
| Strengths | 12 rules, pytest, Splunk/KQL conversion |
| Gaps | CI **failed** (pip pin); no LICENSE until local fix |
| CI root cause | `pysigma-backend-microsoft365defender>=1.0.0` not on PyPI; fixed to `>=0.3.2` |
| Local pytest | **4 passed** |

### security-onion-lab

| Score | 3 → 3.5 / 5 |
|-------|-------------|
| Strengths | Exercise docs, incident template |
| Gaps | Was missing LICENSE, CI, tickets |
| Post local | LICENSE, SECURITY, tickets×3, CI structure job |

### juice-shop-lab

| Score | 3 → 3.5 / 5 |
|-------|-------------|
| Strengths | detections/, compose, blue-team docs |
| Gaps | Same as onion lab |
| Post local | Same remediation pattern |

### JsonCMorgan (profile)

| Score | 3.5 / 5 |
|-------|---------|
| Strengths | Hiring table, honest junior framing |
| Gaps | Missing 2-minute verification block, soc-detection-rules in table, pin guidance |

### job-app-copilot

| Score | 2 / 5 |
|-------|-------|
| Note | Has SECURITY.md; stale for cyber brand; keep private or archive |

### boundry.ai, peta-tools-web

| Score | 1.5 / 5 |
|-------|---------|
| Note | Marketing / pitch; not cyber pins |

---

## Private repo pass (summary)

| Repo | Classification | SDLC note |
|------|----------------|-----------|
| boundry-mcp-server | **Public stub candidate** | Small (8 KB); expose README + architecture on public `boundry-mcp-server-stub` OR keep private with audit doc only |
| geo-audit-tool | Never public | Client/reporting PII risk |
| peta-tools | Never public | Separate marketing stack |
| jason-job-agent | Never public | Resume/agent PII; size 5.9 MB |

**Decision (MCP):** Keep `boundry-mcp-server` **private** until a sanitized **public stub** repo ships (tool names + diagram only, no API keys). Reference `docs/LLM_MCP_SECURITY.md`.

No destructive scans were run on private repo contents in this pass; quarterly checklist adds secret skim.

---

## Local / remote drift register

| Path | Remote | `ahead` | `behind` | Notes |
|------|--------|---------|----------|-------|
| C:\Dev\MSSP | boundry-ai-soc-platform | 0 | 0 | New LICENSE/files uncommitted locally |
| C:\Dev\soc-detection-rules | soc-detection-rules | uncommitted | 0 | CI fix + SDLC files |
| C:\Dev\security-onion-lab | security-onion-lab | uncommitted | 0 | Evidence + CI |
| C:\Dev\juice-shop-lab | juice-shop-lab | uncommitted | 0 | Evidence + CI |
| C:\Users\ricka\Documents\JsonCMorgan | JsonCMorgan | uncommitted | TBD | Profile README |

---

## CI status snapshot (2026-11-22)

| Repo | Latest main workflow | Result |
|------|----------------------|--------|
| boundry-ai-soc-platform | CI push 2026-11-21 | **success** |
| soc-detection-rules | CI push 2026-11-21 | **failure** (deps) |
| security-onion-lab | none | n/a |
| juice-shop-lab | none | n/a |
| JsonCMorgan | Pages | **success** |

---

## Branch protection (documented, not applied)

GitHub Free on personal account: enable on `boundry-ai-soc-platform` **main**:

- Require PR before merge (solo dev: optional self-merge after CI)
- Require status checks: `Secrets scan`, `Lint`, `Tests`
- No force push

Track in PRE_CLIENT checklist or when first paying client onboarded.

---

## Remediation roadmap (30 / 60 / 90 days)

### Days 0–30 (credibility)

- Push local commits (all repos).
- Apply `gh repo edit` topics/descriptions.
- Profile UI pins + verification README merge.
- Confirm soc-detection-rules CI green on GitHub.

### Days 31–60 (evidence)

- Add 1 redacted screenshot per lab.
- Link G# skills in flagship README to `docs/soc-l1-skills-roadmap.md`.
- Optional OpenSSF Scorecard CLI on flagship.

### Days 61–90 (advanced)

- CodeQL (optional) on `app.py` surface.
- Public MCP stub repo decision executed or rejected in writing.
- Export `PORTFOLIO_VERIFICATION_GUIDE.md` to PDF for applications.

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

*This document may contain notes on private repos. Do not copy private-repo rows into public profile README.*