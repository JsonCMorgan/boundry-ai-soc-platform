# Boundry.AI — Incident Response Playbooks

This folder contains all incident response playbooks for the Boundry.AI SOC platform.
Each playbook exists in two formats — one for each side of the business.

---

## Structure

```
playbooks/
├── yaml/          Tech side — structured data, loaded by the SOC platform
├── markdown/      Business side — plain-language, human-readable without any tools
└── README.md      This file
```

---

## Playbook Library

| ID | Title | Severity | YAML | Markdown |
|---|---|---|---|---|
| ransomware | Ransomware Attack Response | CRITICAL | yaml/ransomware.yaml | markdown/ransomware.md |
| phishing_bec | Phishing & Business Email Compromise | HIGH | yaml/phishing_bec.yaml | markdown/phishing_bec.md |
| data_breach | Data Breach & Exfiltration | CRITICAL | yaml/data_breach.yaml | markdown/data_breach.md |
| account_compromise | Account Compromise & Credential Theft | HIGH | yaml/account_compromise.yaml | markdown/account_compromise.md |
| insider_threat | Insider Threat Response | HIGH | yaml/insider_threat.yaml | markdown/insider_threat.md |

---

## Formats Explained

### YAML (Tech Side — `yaml/`)
Used by the SOC platform. Contains full structured data: phases, steps, regulations, MITRE
technique mappings, indicators, and do-not lists. Loaded by `playbook_loader.py` and rendered
in the platform at `/playbooks/<id>`.

Readable by a human in any text editor, even if the platform is completely down.
YAML is plain text — no special viewer required.

### Markdown (Business Side — `markdown/`)
Written for Peta and clients. Plain language, no jargon, explains the "what" and "why"
alongside the "how." Designed to be readable by a non-technical person who needs to
understand what's happening and what decisions need to be made.

Readable in any text editor, any browser, any markdown viewer, or printed as a document.

---

## Adding a New Playbook

1. Create `yaml/<id>.yaml` — follow the structure of an existing YAML file
2. Create `markdown/<id>.md` — write it for a smart non-technical reader (Peta test: would she understand this?)
3. The platform will auto-discover it on next restart (no code changes needed)

---

## If Everything Technical Fails

If the platform is down and you need a playbook:

1. Open any text editor (Notepad, TextEdit, VS Code)
2. Navigate to `playbooks/markdown/`
3. Open the relevant `.md` file
4. Read it — it's written to be followed without a computer if necessary

The markdown files are intentionally kept free of technical dependencies.
They are the paper version of the playbook.

---

*Boundry.AI SOC Platform · Jason Morgan*
