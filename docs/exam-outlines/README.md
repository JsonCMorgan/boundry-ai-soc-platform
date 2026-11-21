# Exam outlines (local vendor PDFs)

Boundry uses **official exam objective PDFs as the coverage spine**. We do **not** ship CompTIA or ISC2 dumps, question banks, or copyrighted PDF text in git.

## North star: SY0-801

CompTIA Security+ **SY0-801** (V8, objectives document version **2.0**) is the curriculum north star. Exam refresh is targeted around **November 2026**. Jason plans to sit near that window.

Existing Boundry Sec+ lessons / quizzes were authored for **SY0-701**. They stay useful during transition (same five-domain shape, many overlapping ideas). New content and retags should target **801**.

Tracked here:

| Path | Tracked? | Role |
|------|----------|------|
| `README.md` (this file) | yes | How to obtain official PDFs |
| `sy0-801-objectives.json` | yes | Official 801 matrix (PDF-verified) + 701→801 crosswalk |
| `comptia-sy0-801-exam-objectives.pdf` | **no** (gitignored) | Official CompTIA SY0-801 objectives |
| `sy0-701-objectives.json` | optional | Legacy 701 seed (if present); not the north star |
| `comptia-sy0-701-exam-objectives.pdf` | **no** (gitignored) | Optional legacy 701 PDF |
| `isc2-cissp-exam-outline.pdf` | **no** (gitignored) | Official ISC2 CISSP outline (later) |
| `_*-extract.txt` | **no** (gitignored) | Temporary PDF text extracts; delete after JSON build |

Related Boundry files:

- Coverage status page: [`../secplus-objective-coverage.md`](../secplus-objective-coverage.md)
- Audit tool: `tools/secplus_coverage_audit.py`
- Lesson spine (still 701-tagged): `secplus_lessons.py` → `DOMAINS` / `LESSONS` / `objective_ref`

---

## CompTIA Security+ (SY0-801) — Jason drop instructions

1. Obtain the official **Security+ SY0-801** exam objectives PDF from CompTIA (not dumps).
2. Save locally as:

   `docs/exam-outlines/comptia-sy0-801-exam-objectives.pdf`

3. Re-run coverage:

   ```text
   python tools/secplus_coverage_audit.py
   ```

4. If the PDF is updated (new document version), re-extract into `sy0-801-objectives.json`:
   - Confirm every objective `id` + `title` + `sub_topics`
   - Keep `pdf_verified: true`
   - Bump `version_label` to the PDF’s document version (e.g. `2.0`)
   - Refresh `crosswalk_from_sy0701` if CompTIA renumbers again

**Legal / product rule:** Official objectives are the outline for Boundry’s original lessons and quizzes. Never commit vendor PDF body text, CompTIA practice items, or reconstructed dumps.

### Domain weights (SY0-801 V8)

| Domain | Title | Weight |
|--------|-------|-------:|
| 1.0 | General Security Concepts | 16% |
| 2.0 | Threats, Vulnerabilities, and Attacks | 24% |
| 3.0 | Security Architecture | 19% |
| 4.0 | Security Operations | 27% |
| 5.0 | Security Program Management and Oversight | 14% |

vs SY0-701 Boundry seed weights: 12 / 22 / 18 / 28 / 20. Notable: Domain 1 heavier, Domain 5 lighter, Domain 2 renamed (Mitigations → Attacks) and mitigation content moved into Domain 4.

---

## Legacy SY0-701 (transition only)

Keep using current Boundry lessons tagged with 701 `objective_ref` values. The audit crosswalks them onto 801. Do **not** delete 701-aligned lessons; mark gaps against 801 and fill those first.

Optional: if you still have a 701 PDF, save as `comptia-sy0-701-exam-objectives.pdf` (gitignored). Not required for the 801 north-star pipeline.

---

## ISC2 CISSP (later)

1. Open: [https://www.isc2.org/certifications/cissp/cissp-exam-outline](https://www.isc2.org/certifications/cissp/cissp-exam-outline)
2. Download the official CISSP exam outline PDF.
3. Save as:

   `docs/exam-outlines/isc2-cissp-exam-outline.pdf`

4. A future `cissp-objectives.json` + CISSP coverage audit can mirror the Sec+ pipeline.

---

## What works before vs after the 801 PDF

| Stage | What works |
|-------|------------|
| **Before 801 PDF** | Boundry 701 spine only. Gap hunting is approximate. |
| **After 801 PDF + JSON** (current) | Coverage gaps against the **official 801** matrix become trustworthy for curriculum planning. Crosswalk shows still_valid / changed / new_on_801. |
| **Never** | Auto-scraping CompTIA dumps, committing PDF text, or treating 701 IDs as 801 IDs without the crosswalk. |
