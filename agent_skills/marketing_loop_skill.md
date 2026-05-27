# Skill: Marketing Loop

**Trigger:** Jason says "run marketing loop", "write a post", "draft LinkedIn [topic]", or "write Substack [topic]"

---

## Purpose

Turn real security findings and incidents from Boundry.AI into educational content that:
- Positions Jason as a practitioner (not just a vendor)
- Attracts cannabis/small-business clients who don't know they need a SOC
- Builds the Boundry.AI brand without paid ads

The rule: **every post teaches something real, uses real data (anonymised), and ends with a soft CTA.**

---

## Step 1 — Pick a Content Source

Ask Jason which source to pull from (or pick for him if he says "surprise me"):

| Source | What to look for |
|---|---|
| Recent SIEM findings | Any CRITICAL/HIGH finding from the last 7 days |
| Weekly report | Most interesting threat from the latest PDF |
| Training scenario | A scenario Jason just completed (CISSP tie-in) |
| Industry news | A breach that hit a cannabis/retail/small biz this week |
| Jason's own question | Something he just learned and wants to explain |

---

## Step 2 — Extract the Story

From the chosen source, identify:

- **The attack type** (brute force, SQLi, credential stuffing, etc.)
- **What the attacker was trying to do** (MITRE tactic)
- **What stopped it** (or what would have stopped it)
- **The lesson for a non-technical business owner**

Anonymise all specifics: no real IPs, no client names, no internal hostnames.

---

## Step 3 — Write LinkedIn Post

Format: hook → story → lesson → CTA. Max 1,300 characters (LinkedIn sweet spot).

Template:

```
[HOOK — one sentence that makes a business owner stop scrolling]

[2–3 sentences: what happened, written like a story not a tech manual]

Here's what the logs showed:
→ [1–2 specific detail, anonymised, e.g. "47 failed logins in 33 minutes"]
→ [what it meant]

[One sentence: what would have prevented this]

[Lesson for a business owner in plain English]

If you're running [industry] and don't have someone watching your logs —
this is what that looks like. DM me or visit boundry.ai

#CyberSecurity #SmallBusiness #SIEM #[Industry]
```

Show Jason the draft. Ask: "Post as-is, edit, or save for later?"

---

## Step 4 — Write Substack Article (optional)

If the topic warrants more depth (breach walkthrough, MITRE explainer, CISSP concept), write a 400–600 word article:

```
Title: [Attention-grabbing, search-friendly]
Subtitle: [One sentence that explains what the reader will learn]

---

[Opening: the scenario or problem — 2 sentences]

[Section 1: What happened / what the attack looks like — 150 words]

[Section 2: What the logs showed — use a code block or table for the data]

[Section 3: How to defend against it — 3 bullet points, actionable]

[Closing: one sentence connecting this to Boundry.AI's work]

---
Jason Morgan is a cybersecurity analyst and the founder of Boundry.AI,
a managed security service built for small businesses.
boundry.ai | jason@boundry.ai
```

---

## Step 5 — Content Calendar Entry

After drafting, suggest a schedule:

```
LinkedIn: Post [day] at 8am [timezone] (Tuesday/Thursday perform best)
Substack: Publish [day] — aim for 1x per week max
```

Remind Jason: Cursor can post to LinkedIn and Substack directly via MCP once OAuth is connected.

---

## Recurring Triggers

Run this skill automatically when:
- A new CRITICAL finding is generated (offer to draft a post from it)
- Jason completes a CISSP domain (offer a "what I learned" post)
- A weekly report is generated (offer a sanitised highlight post)
