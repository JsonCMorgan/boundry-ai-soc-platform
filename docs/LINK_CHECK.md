# Link check

**Public product:** `C:\Dev\link-check` → `python public_app/app.py` (port **5055**) or deploy Docker image. Share that URL with recruiters; do not send them to the full MSSP.

## Surfaces

| Where | URL / command |
|--------|----------------|
| **Public web (primary)** | `http://127.0.0.1:5055` locally; deployed URL when live |
| Boundry (legacy / personal) | `/ops/link-check` after analyst login |
| CLI | `python -m link_check "..." --claimed "..."` |

Logic lives in the **link-check** package. Boundry loads it via `link_triage.py` (sibling path or `pip install -e`).

## Privacy

v0.1 is **offline**: no HTTP fetch to the link, no VirusTotal unless you add opt-in later.

## Your Intact / Paradox case

Claimed brand **Intact Financial** + host **olivia.paradox.ai** → `do_not_click` (brand mismatch + recruiting vendor). Verify on **intact.ca** careers only.