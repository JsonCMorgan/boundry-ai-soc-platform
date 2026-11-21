# Writing Coach UX

Boundry stacks a **Writing Coach** panel above every in-scope textarea so rubrics stay visible while typing. HTML `placeholder` text disappears on focus, so multi-item checklists never belong in placeholders.

## Layers

| Layer | Purpose |
|--------|---------|
| **Coach panel** | Numbered rubric, syntax steps, or "include these elements" |
| **Placeholder** | One short example line max (from `placeholder_example` in registry) |
| **Field `hint`** (ticket console) | Optional one-line; coach carries the multi-line guidance |

## Adding a coached field

1. Add or reuse an entry in `note_coaches.py` (`COACHES` dict).
2. In the template: `{% include '_writing_coach.html' %}` once per page (CSS + JS), then `{% from '_writing_coach.html' import writing_coach_from_registry %}` and call `writing_coach_from_registry('your_coach_id')` above the textarea.
3. On the textarea: `aria-describedby="coach-your_coach_id"`, `data-writing-coach="your_coach_id"`, placeholder from `get_coach(...)['placeholder_example']`.
4. For JS-rendered fields (ticket console, interview gym): use `WritingCoach.buildHtml(...)` and the same `aria-describedby` / `data-writing-coach` attributes.
5. Run `python tools/note_coach_audit.py --strict` before release.

## Ticket Field Console

Textarea fields in `ticket_fields.STANDARD_FIELDS` use `coach_id`. `fields_for_ui()` attaches full coach copy for `TicketFields.mount()`.

## Exclusions

Login, register, 2FA, password fields, and single-line search/filter inputs are not writing-coach surfaces.

## Tutor voice

Coach copy should define acronyms on first use in that panel (see `.cursor/rules/tutor-professor-voice.mdc`).
