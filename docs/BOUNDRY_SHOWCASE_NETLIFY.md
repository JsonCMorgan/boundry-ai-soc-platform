# Boundry portfolio showcase (Netlify)

Static recruiter/hiring-manager tour with screenshots. No Flask on the public internet.

## 1. Capture screenshots (PC, once)

Start Flask on port 5000 (normal `python app.py` is fine).

Set your analyst login (required for most pages):

```powershell
$env:ANALYST_PASSWORD = "your-analyst-password"
# optional: $env:SHOWCASE_USER = "your-username"
cd C:\Dev\MSSP
python tools/capture_boundry_showcase_screenshots.py
```

Output: `public/boundry-showcase/images/*.png`

`/demo` (client reports) works without analyst login.

## 2. Same Netlify site as your conference QR (recommended)

Your QR already opens `https://fanciful-fox-c753db.netlify.app/index.html`.

```powershell
cd C:\Dev\MSSP
.\tools\sync_showcase_to_netlify_card.ps1
python C:\Users\ricka\Projects\jason-job-agent\scripts\build_digital_business_card.py
```

Then in Netlify, **re-deploy** the folder `jason-job-agent\profile\digital_card` (drag-and-drop replace, same site).

Tour URL: **`https://fanciful-fox-c753db.netlify.app/hq/`**

**LinkedIn:** Hub + vCard use `profile/digital_card/config.json` → `linkedin_url`. The sync script injects the same URL into the tour footer (`LinkedIn` button).

The contact card gets a green **Boundry HQ tour** button. **You do not need a new QR code**; scanners still land on your hub, then tap the tour.

## 2b. Standalone Netlify site (optional)

Deploy only `public/boundry-showcase` if you want a separate URL without the digital card.

## 3. Conference use

Share the Netlify URL or QR code. The site is a **scroll tour** (boot sequence, chapter briefs, full-bleed screenshots). Label it **portfolio preview**, not a live client portal.

**Talking track:** "Clock in as a visitor, scroll the ops floor, SIEM, SOC shift, client portal, then the career wing."

Update after major UI changes: re-run the capture script and redeploy the folder.

## 4. Local preview

```powershell
start C:\Dev\MSSP\public\boundry-showcase\index.html
```