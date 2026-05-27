# How to Use Step Skills — Boundry.AI

Boundry.AI skills are **step files** the Cursor agent executes in a loop. Adapted from Justin Girard's CursorSkillsBundle discipline for Jason Morgan's agent operations.

## The loop

Every skill run follows four phases. **Never skip a phase.**

```
CONCEPT → EDIT → REVISION_COMPLETE → TASK_COMPLETE
```

| Phase | What happens |
|-------|----------------|
| **CONCEPT** | Read the skill file end-to-end. Read (or create) the progress file. Confirm inputs (client name, finding ID, date range). State what you will produce. |
| **EDIT** | Do one bounded chunk of work. Update the progress file **before** moving on. |
| **REVISION_COMPLETE** | Self-check against the skill's Verification section. Fix gaps in the same loop if needed. |
| **TASK_COMPLETE** | All artifacts exist. Verification checklist passed. Mark progress file status `TASK_COMPLETE`. Tell Jason what to do next (Stripe, email, delivery). |

## Non-negotiables

1. **Re-read the skill every loop** — skills change; do not rely on memory from earlier in the chat.
2. **Progress file is authoritative** — if chat history and progress file disagree, trust the progress file.
3. **One progress file per run** — path is defined in each skill's Artifacts section.
4. **No app.py edits during skill runs** unless Jason explicitly asks for a code change.
5. **Privacy first** — Ollama local AI for client data; Anthropic only as fallback (see `.cursorrules`).

## Starting a skill

```
@weekly_siem_report_skill for client ACME
```

Or reference the skill file directly:

```
Read agent_skills/weekly_siem_report_skill.md and run it for client GreenLeaf Dispensary.
```

## Resuming interrupted work

```
Read agent_tasks/weekly_siem_report_acme_2026-05-27_progress.md and continue from the last incomplete step.
```

## Skill index

| Trigger phrase | Skill file |
|----------------|------------|
| weekly report, SIEM report | `weekly_siem_report_skill.md` |
| client onboarding, new client | `client_onboarding_skill.md` |
| triage finding, HIGH finding, CRITICAL finding | `new_finding_triage_skill.md` |

## Revenue priority (Path A)

When Jason asks "what makes money this week" — run **Weekly SIEM Report** first, then Stripe subscription verification.
