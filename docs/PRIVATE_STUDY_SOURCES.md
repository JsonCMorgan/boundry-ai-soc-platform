# Private study sources (Jason personal use)

## Purpose

Boundry ships **original** Security+ curriculum in git. Separately, Jason may ingest **paid, licensed** study packs for **local, personal** use on his machine only.

## Exam version

**SY0-701** matches the current Messer pack (`manifest.json` → `detected_version`). Treat 701 objectives and session numbering as canonical for study until 801 Messer materials exist.

## Professor Messer Security+

- **Location:** `C:\Dev\MSSP\content\private\messer\` (gitignored, on your SSD). Optional override: `MESSER_CONTENT_ROOT`. **OneDrive is not used** unless you set `MESSER_FALLBACK_ONEDRIVE=1`.
- **Use:** Practice exams, course notes excerpts, exam hacks, PBQs, transcripts for recall and Daily Review
- **Not for:** Git commits, public repos, client demos, or `/demo` when `ENABLE_MESSER_LAYER` is unset

## Engineering rules

1. Code and empty schemas may live in the repo; **verbatim Messer text/media may not**.
2. Messer items in SQLite use `messer:*` IDs and `track=messer` in the retention layer.
3. Cloud transcription or upload of Messer assets is out of scope (local Whisper/sidecars only).

## Feature flag

Set `ENABLE_MESSER_LAYER=1` on Jason's dev machine to expose Messer routes in the UI. Production and demo should leave it unset.

Optional: `USE_MESSER_MINI=1` adds up to 3 Messer MCQs to retention after each Sec+ Prove pass.

### Hybrid quizzes (default): notes Help + notes Prove

| Mode | Help-me | Prove-it |
|------|---------|----------|
| **Hybrid (default)** | **3** MCQs from session course notes (Ollama) | **Minimum 5** MCQs from the same notes (harder application) |
| Exam MCQs | Stored in `practice_exam_fallback` for Help fallback only | Not used for Prove-it |

Quality: deterministic guards ([`notes_quiz_guards.py`](C:\Dev\MSSP\notes_quiz_guards.py)) + local Ollama verifier per MCQ (`MESSER_QUIZ_SKIP_VERIFY=1` only for dev).

Workflow:

1. Rebuild spine: `python tools/messer_build_curriculum.py` (sets `practice_exam_fallback`, empty Prove until batch).
2. Ollama running (`llama3.1:8b` or `OLLAMA_MODEL`).
3. One lesson (Help + Prove): `python tools/messer_generate_notes_quizzes.py --lesson ms_0101_01`
4. Prove batch only: `python tools/messer_generate_notes_quizzes.py --prove-only`
5. **Full batch:** `python tools/messer_generate_notes_quizzes.py` then `--prove-only` for any gaps.  
   Log: `content/private/messer/curriculum/notes_quiz_batch.log`. Resume skips complete banks.  
   Strict audit: `python tools/messer_notes_quiz_audit.py --strict`
6. **Answer-key audit (finish before trusting every key):**
   - **Run to completion** (keep Ollama up; use a standalone PowerShell window):
     `powershell -ExecutionPolicy Bypass -File tools/messer_run_quiz_audit.ps1`
   - **Progress:** `python tools/messer_quiz_audit_status.py`
   - Report: `content/private/messer/curriculum/quiz_answer_verify_report.json` (`complete: true` ≈ 910 items).
   - **After audit:** skim `failures`, then `python tools/messer_verify_quiz_answers.py --apply` for clear Ollama `better_index` fixes.
   - **Bad lessons:** `python tools/messer_generate_notes_quizzes.py --lesson ms_XXXX_XX --force` then re-run audit for that lesson.
   - **While studying:** if a key disagrees with Show-me **Course notes**, trust the notes and file the lesson id for patch/regen.
6. Cache: `content/private/messer/curriculum/notes_quizzes/` (gitignored). `--force` after notes change.

## Sync pipeline

### Local-only setup (recommended)

1. Copy your **paid Messer files** from wherever they truly live on disk (browser **Downloads**, a USB stick, an extracted zip, etc.) into:

   `C:\Dev\MSSP\content\private\messer\`

   Keep the usual layout: PDFs at the root or subfolders, `sy0-701-audio\`, video folders, etc.

2. Ingest (reads **only** that folder, no cloud):

```powershell
cd C:\Dev\MSSP
pip install -r requirements-dev.txt
python tools/messer_sync_all.py
```

With `ENABLE_MESSER_LAYER=1`, `/career/secplus` uses **121 Messer sessions** as the lab spine (Show-me from course notes, Help-me/Prove from imported exam items). Rebuild curriculum only: `python tools/messer_build_curriculum.py`.

Show-me uses **course notes** (and a **Transcript** section when `content/private/messer/transcripts/{audio-stem}.txt` exists). Rebuild: `python tools/messer_build_curriculum.py`.

3. In your env: `ENABLE_MESSER_LAYER=1`

If you already mirrored most files via robocopy, you are done with step 1. The missing firewall `.txt` is optional; the PBQ uses **Practice Exam A5** from the practice-exams PDF after extract.

### OneDrive (optional, not required)

Use this only if you still keep the canonical copy in OneDrive and want a one-time copy to the SSD:

```powershell
powershell -ExecutionPolicy Bypass -File C:\Dev\MSSP\tools\messer_mirror.ps1
```

That script reads OneDrive; Boundry itself does **not** need OneDrive running day to day.

## Home LAN study (laptop → office PC)

Goal: open Boundry Sec+ / Messer notes and tests from a **laptop on home Wi‑Fi**, while **progress, `app.db`, and Messer files stay on the office PC**. Do not copy `content/private/messer/` to the laptop or sync study progress to Railway for this.

### Office PC (one-time)

1. Keep `ENABLE_MESSER_LAYER=1` as you already do for Messer.
2. Bind Flask to the LAN (default is localhost-only):

```powershell
$env:FLASK_BIND_HOST = "0.0.0.0"
# optional: $env:FLASK_PORT = "5000"
python app.py
```

3. **One-time elevated setup** (firewall Private-only + set LAN to Private). Right-click PowerShell → Run as administrator:

```powershell
powershell -ExecutionPolicy Bypass -File C:\Dev\MSSP\tools\enable_home_lan_flask.ps1
```

That script creates the inbound **TCP 5000 / Private** rule, tries to set Ethernet/Wi‑Fi to **Private** (skips NordVPN adapters), and prints your laptop bookmark URL.

Manual equivalent if you prefer:

```powershell
# Elevated PowerShell
New-NetFirewallRule -DisplayName "Boundry Flask LAN (Private)" `
  -Direction Inbound -Protocol TCP -LocalPort 5000 `
  -Action Allow -Profile Private
```

4. Confirm the office PC **physical** network is **Private** (Settings → Network → Ethernet/Wi‑Fi → Private). If it stays Public, the Private firewall rule will not apply and the laptop will be blocked.
5. Note the office LAN IP (physical NIC, not NordLynx / OpenVPN). On this office PC that is often `10.0.0.2` on Ethernet.

Example bookmark: `http://10.0.0.2:5000/career/secplus` (confirm with the script output or `ipconfig`).

### Laptop (each study session)

1. Same home SSID as the office PC.
2. Open `http://OFFICE-IP:5000`, log in as your analyst user.
3. Use `/career/secplus` and `/career/secplus/messer` as usual. Help-me / notes quizzes still call **Ollama on the office PC**.

### Keep the office PC ready

- Flask running with `FLASK_BIND_HOST=0.0.0.0` and `ENABLE_MESSER_LAYER=1`.
- Ollama running if you need Help-me / quiz AI.
- Do not let the office PC sleep while you study from the laptop.

### Safety checks

- From the office PC: `http://127.0.0.1:5000/career/secplus` still works.
- From the laptop on home Wi‑Fi: notes load; Prove / exam attempts show up in office `app.db`.
- From a phone hotspot (not home LAN): should **fail** (Public profile / different network).
- Do **not** port-forward 5000 on the router or bind this for public internet access.

Optional later (same “progress on office PC” model): Tailscale/WireGuard for cafe/travel. Not part of this Home LAN setup.
