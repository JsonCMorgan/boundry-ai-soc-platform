# GitHub portfolio re-audit checklist

Run **monthly** (or before a heavy interview week). Time box: 45 minutes.

## 1. Account surface (10 min)

- [ ] Profile bio, location (GTA Canada), company, hireable flag match `docs/PORTFOLIO_VERIFICATION_GUIDE.md`
- [ ] Pinned repos order: boundry-ai-soc-platform, soc-detection-rules, security-onion-lab, juice-shop-lab
- [ ] Profile README verification block still accurate (links, CI badges)
- [ ] No new open issues on profile repo that dilute cyber brand (issues currently **disabled** on `JsonCMorgan/JsonCMorgan`)

## 2. CI and drift (15 min)

```powershell
gh run list -R JsonCMorgan/boundry-ai-soc-platform -L 1
gh run list -R JsonCMorgan/soc-detection-rules -L 1
gh run list -R JsonCMorgan/security-onion-lab -L 1
gh run list -R JsonCMorgan/juice-shop-lab -L 1
cd C:\Dev\MSSP; git fetch origin; git log origin/main..HEAD --oneline
```

- [ ] All four repos: latest `main` run **success** (or documented exception)
- [ ] Local `C:\Dev\MSSP` has zero unpushed commits before client demos (or push after Jason confirms)

## 3. OpenSSF-style file check (10 min)

For each public **code** repo (boundry, detection-rules, both labs):

- [ ] `LICENSE` present
- [ ] `SECURITY.md` present
- [ ] Description + topics on GitHub match hire narrative
- [ ] Dependabot config on Python repos (boundry, soc-detection-rules)

## 4. Evidence layer (10 min)

- [ ] At least 2 sanitized tickets per lab repo under `tickets/`
- [ ] `screenshots/README.md` policy unchanged; new images redacted
- [ ] soc-detection-rules: rule count and MITRE table match `rules/`

## 5. Private repos (non-destructive)

- [ ] No `.env` or client identifiers committed (`gh` clone skim or `gitleaks` locally)
- [ ] `boundry-mcp-server` classification unchanged (see audit: **public stub** vs private)
- [ ] `jason-job-agent` stays private; no resume PII in remote

## 6. Score and log

- [ ] Update **Overall maturity** line in `docs/GITHUB_INDUSTRY_AUDIT.md` (date + score)
- [ ] File follow-ups in Boundry task list or career roadmap

## Quick commands

```powershell
gh api user --jq '{bio, location, company, hireable}'
gh repo list JsonCMorgan --limit 20 --json name,visibility,pushedAt,description
```