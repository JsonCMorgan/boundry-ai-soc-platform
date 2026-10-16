# Boundry.AI — Privacy / data handling (M7)

**Status:** Living one-pager for this phase  
**Last updated:** 2026-10-11  
**Matches PRD Q6:** client and ops data **never leave the machine** for AI processing.

## What Boundry stores locally

- Analyst accounts, session state, Career training progress  
- SIEM events, findings, `/soc` cases, reports, portfolio notes  
- Practice (simulated) client labels for training  

SQLite default: `C:\Dev\MSSP\app.db` (or Postgres via `DATABASE_URL` when configured).

## AI processing

- **Primary:** local Ollama on this host  
- **Not used this phase for client/ops data:** Anthropic or other cloud LLMs  
- Career Tutor and report drafts must stay Ollama-first when content could include ops or client-like data  

## What we do not do this phase

- Send client or ops payloads to cloud AI  
- Present Practice queue items as real client incidents  
- Share demo-seeded reports as another tenant’s real data  

## Access

- Analyst role: full command center  
- Client / demo roles: reports (and related portal views) only; ops and Career routes blocked  
- Demo account sees only its own seeded reports (`owner_id` scoped)

## Retention / backups

- Operational evidence lives in `app.db`  
- Daily backup via `tools/backup_app_db.ps1` (M6)  
- Retention of backups: last 14 copies by default  

## Contact for changes

Jason owns Must changes in the PRD. Revisit this page when Roy partnership or first paying client goes live.
