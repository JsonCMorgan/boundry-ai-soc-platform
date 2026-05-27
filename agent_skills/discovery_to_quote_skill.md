# Skill: Discovery → Quote

**Trigger:** Jason says "run discovery quote", "new client quote", or "write up [client name] quote"

---

## Step 1 — Capture Call Notes

Ask Jason for the following (accept partial answers — fill gaps with sensible defaults):

```
Client name:
Industry / sector:
Company size (headcount or revenue rough guess):
Current security tools (if any):
Main pain points (what prompted the call):
Compliance requirements mentioned (PCI, HIPAA, SOC 2, GDPR, etc.):
Decision-maker on the call:
Timeline they mentioned:
Budget signals (any number mentioned, or "no budget talk yet"):
Next step agreed on call:
```

If Jason pastes raw call notes instead of a structured form, extract the above fields from them.

---

## Step 2 — Scope the Engagement

Based on the answers, recommend a service tier and list what's included:

### Tier A — Starter Monitoring ($X/mo)
- SIEM event ingestion (up to 10k events/day)
- Weekly automated threat report (PDF, emailed)
- Incident alert by email on CRITICAL findings
- Monthly 30-min review call

### Tier B — Active Defence ($X/mo)
- Everything in Tier A
- Real-time correlation rules tuned to their stack
- Splunk HEC integration (if they have Splunk)
- 2x monthly calls + ad-hoc Slack alerts
- Quarterly vulnerability scan of their external surface

### Tier C — Managed SOC ($X/mo)
- Everything in Tier B
- Dedicated analyst response (SLA: 4h acknowledge, 24h remediation plan)
- Custom MITRE ATT&CK coverage mapping
- Staff security awareness training (1x session/quarter)
- Annual penetration test planning

Ask Jason: "Does Tier [recommended] fit, or do you want to adjust scope?"

---

## Step 3 — Generate Quote Document

Write a plain-English scope-of-work document (not a legal contract — that's the MSA):

```
BOUNDRY.AI — SECURITY SERVICES PROPOSAL
Prepared for: [Client Name]
Date: [Today]
Prepared by: Jason Morgan, Boundry.AI

SCOPE OF WORK
[2–3 sentences summarising what we'll do based on their pain points]

SERVICES INCLUDED
[Bullet list from chosen tier]

WHAT WE NEED FROM YOU
- API key / log forwarding access
- Point of contact for escalations
- [Any client-specific items from call notes]

INVESTMENT
[Tier name]: $[price]/month
Setup fee (one-time): $[price] (waived if contract ≥ 6 months)
Contract term: [month-to-month / 3-month / 6-month / 12-month]

NEXT STEPS
1. Review and sign MSA (link)
2. Schedule 1-hour onboarding call
3. We deploy and configure within [X] business days

Questions? jason@boundry.ai
```

---

## Step 4 — Stripe Invoice (when Jason confirms)

Only proceed when Jason says "send it" or "create the invoice".

Remind Jason: you need Stripe MCP connected (OAuth in Cursor) to create invoices from here. Until then, provide:

```
Stripe invoice line items to enter manually:
- Description: [Tier name] — Monthly Retainer
  Amount: $[price].00
  Recurring: Monthly

- Description: Setup & Onboarding Fee
  Amount: $[price].00
  One-time

Customer email: [from call notes]
```

---

## Memory

After completing a quote, append to memory:

```
Client: [name] | Industry: [X] | Tier: [A/B/C] | MRR: $[X] | Status: Quote sent [date]
```
