# Memory retention UX (Boundry Retention Layer)

## Purpose

Career and cert study should optimize for **long-term recall**, not one-and-done Prove passes.
The Retention Layer adds **spaced review**, **retrieval with feedback**, and **mixed decks**
while keeping all schedule data in local `app.db` (no cloud sync).

## Surfaces

| Surface | Route / API | Role |
|---------|-------------|------|
| Daily Review session | `GET /career/review` | Up to 10 due cards; MCQ, flashcard, teach-back, 72h mini-quiz |
| Due widget | Career hub hero | "Review due: N" + link |
| FSRS scheduling | `memory_retention.py` | Again / Hard / Good / Easy after feedback |
| Enroll hooks | Prove, Help-me miss, labs, shift, training | Auto-queue authored items only |

## Session flow

1. Pick **Mix** (default, interleaved) or **Focus** (`?mode=focus&track=secplus`).
2. Show prompt (never reveal answer on MCQ until submit).
3. **Feedback** in tutor voice: correct / trap / remember.
4. Rate difficulty → FSRS sets next `due_at`.
5. Soft **anti-cram** nudge after 30 reviews in one day.

## Enroll rules (summary)

- **Sec+ Prove pass:** 3–5 quiz items + optional teach-back + **72h mini-quiz** (3 questions).
- **Sec+ Prove fail / Help-me wrong:** missed items due **immediately**.
- **Sec+ terms:** per-term or "Add all" on `/career/secplus/terms`.
- **Net / Logs hub:** "Add flashcards to Review".
- **SPL / KQL / Net prove:** sample of graded items; wrong items prioritized.
- **Intel / Vuln case pass:** one cold-recall card from case `teach` text.
- **Shift complete:** MITRE-tagged follow-up flashcard (~48h).
- **Training scenario submit:** re-run reminder (~72h).

## Pedagogy (product rules)

1. Prove pass **starts** spacing; it does not remove mastery gates.
2. Teach-back blocks may be **added to Review** from the lesson page.
3. Labs should set expectation: short check appears in tomorrow's queue.
4. Mix mode weights: ~40% Sec+, ~30% net/logs, ~30% labs/SPL/KQL (config in `MIX_WEIGHTS`).

## Privacy

Review logs and FSRS state stay on-machine. No Anki sync, no third-party SRS cloud.

## Related code

- `memory_retention.py` — registry, enroll, due queue, FSRS
- Tables: `retention_items`, `retention_cards`, `retention_reviews`
- Tests: `tests/test_memory_retention.py`
