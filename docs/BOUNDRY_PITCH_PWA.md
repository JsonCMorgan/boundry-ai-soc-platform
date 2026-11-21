# Boundry Pitch Quiz (offline PWA)

Phone drill for explaining Boundry.AI to recruiters and hiring managers.

## Open

1. On the PC (PowerShell), start **LAN pitch mode** (uses port **8765**, not 5000):

```powershell
cd C:\Dev\MSSP
.\tools\launch_pitch_phone.ps1
```

Boundry port hardening **blocks inbound TCP 5000** from the LAN. Phones must use **8765**.

One-time (Administrator): `.\tools\ensure_pitch_phone_firewall.ps1` if 8765 was never allowed.

2. On your phone (same Wi-Fi as the PC): `http://<PC-LAN-IP>:8765/pitch`
   (Example: `http://10.0.0.2:8765/pitch`). Use the **Ethernet/Wi‑Fi** IP (`10.0.x.x`), not NordVPN `10.100.x.x`.
   **Do not** use `localhost` on the phone.
3. **iPhone:** Share → Add to Home Screen.
4. Open once online so the service worker caches files. Then works offline.

## Not loading?

- Phone cannot reach `127.0.0.1` — that is the PC only. Use the LAN IP.
- If you see the title but no deck buttons, `quiz-data.js` failed. Hard refresh or clear Safari site data for that host.
- Opening `index.html` from File Explorer (`file://`) will not work.
- **PC works, phone does not:** you are probably on `http://127.0.0.1:5000` on the PC (loopback). Switch to `launch_pitch_phone.ps1` and **8765** on both.
- iPhone **Private Wi‑Fi Address** can confuse bookmarks; use a fresh Safari tab.
- Router **guest Wi‑Fi** or **AP isolation** blocks phone-to-PC; use home LAN SSID.

## Update questions

Golden cards: edit `tools/seed_boundry_pitch_pwa.py`.

More cards (local Ollama, batch):

```powershell
python tools/generate_boundry_pitch_items.py
python tools/seed_boundry_pitch_pwa.py
```

Targets **16 MCQ + 4 flash per deck** (golden kept). Re-run generate for a new batch; merge is deduped.

Hard-refresh or reinstall if the service worker caches an old version.

## Privacy

No accounts. Progress only in browser `localStorage` on your phone.
