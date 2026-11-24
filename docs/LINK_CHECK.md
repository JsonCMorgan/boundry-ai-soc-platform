# Link check

**Public product:** `C:\Dev\link-check` → port **5055** or deploy Docker image. Share that URL with recruiters; do not send them to the full MSSP.

**Local updates:** After template/package changes, run `C:\Dev\link-check\scripts\restart-public-app.ps1` (kills stale listeners, `pip install -e`, restarts). Hard refresh the browser. Cursor rule: `link-check/.cursor/rules/link-check-dev.mdc`.

## Surfaces

| Where | URL / command |
|--------|----------------|
| **Public web (primary)** | `http://127.0.0.1:5055` locally; deployed URL when live |
| Boundry (legacy / personal) | `/ops/link-check` after analyst login |
| CLI | `python -m link_check "..." --claimed "..."` |

Logic lives in the **link-check** package. Boundry loads it via `link_triage.py` (sibling path or `pip install -e`).

## Privacy

v0.2: **offline by default**; optional careers fetch hits only configured employer URLs (never the pasted link). Curated `allowed_vendor_hosts` (e.g. Intact + `paradox.ai`).

## Your Intact / Paradox case

Claimed brand **Intact Financial** + host **olivia.paradox.ai** → `do_not_click` (brand mismatch + recruiting vendor). Verify on **intact.ca** careers only.