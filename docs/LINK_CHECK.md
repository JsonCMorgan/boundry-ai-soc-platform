# Link check (Option B)

Personal/MSSP helper to **paste a URL before you click** (SMS, email, conference follow-ups).

## Surfaces

| Where | URL / command |
|--------|----------------|
| Phone (same LAN) | `http://<pc>:5000/ops/link-check` after analyst login |
| API | `POST /api/ops/link-check` JSON `url`, optional `claimed_brand` |
| PC CLI | `pip install -e C:\Dev\link-check` then `python -m link_check "..." --claimed "..."` |

Logic lives in portfolio repo `C:\Dev\link-check`. Boundry loads it via `link_triage.py` (sibling path or pip install).

## Privacy

v0.1 is **offline**: no HTTP fetch to the link, no VirusTotal unless you add opt-in later.

## Your Intact / Paradox case

Claimed brand **Intact Financial** + host **olivia.paradox.ai** → `do_not_click` (brand mismatch + recruiting vendor). Verify on **intact.ca** careers only.