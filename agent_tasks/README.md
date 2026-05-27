# agent_tasks/

Progress files for Boundry.AI Cursor skills. **One progress file per skill run.**

## Naming

| Skill | Progress file pattern |
|-------|----------------------|
| Weekly SIEM Report | `weekly_siem_report_<client>_<YYYY-MM-DD>_progress.md` |
| Client Onboarding | `client_onboarding_<client>_progress.md` |
| New Finding Triage | `new_finding_triage_<finding_id>_progress.md` |

Example: `weekly_siem_report_acme_2026-05-27_progress.md`

## Rules

1. **Progress file is source of truth** — re-read it at the start of every skill loop.
2. Progress files are **gitignored** (`agent_tasks/*.md` except this README).
3. When resuming after a context reset, tell Cursor: `@boundry-skills resume weekly SIEM report for ACME` and point to the progress file path.
4. Delete or archive progress files only after `TASK_COMPLETE` (see `agent_skills/__how_to_use_step_skills.md`).

## See also

- `docs/AGENT_OPERATIONS.md` — day-to-day workflow
- `agent_skills/` — skill definitions
