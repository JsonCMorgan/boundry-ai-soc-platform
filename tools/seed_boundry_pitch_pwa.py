#!/usr/bin/env python3
"""Write static/boundry-pitch PWA files (offline Boundry quiz)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.boundry_pitch_merge import merge_decks  # noqa: E402
OUT = ROOT / "static" / "boundry-pitch"
# Absolute URLs so /pitch and home-screen icons resolve scripts correctly
PITCH_BASE = "/static/boundry-pitch/"

DECK = {
    "version": 1,
    "title": "Boundry Pitch Quiz",
    "decks": [
        {
            "id": "elevator",
            "name": "Elevator and business",
            "items": [
                {
                    "type": "mcq",
                    "q": "In one sentence, what is Boundry.AI today?",
                    "choices": [
                        "A public bug bounty platform for enterprises",
                        "A private offline-first command center and SOC training lab for SMB security",
                        "A cloud-only MDR for Fortune 500",
                        "A CompTIA exam dump site",
                    ],
                    "answer_idx": 1,
                    "explain": "SIEM, triage, reports, Career Hub on your machine. Pre-revenue. Local Ollama for AI.",
                },
                {
                    "type": "flash",
                    "term": "Offline-first",
                    "prompt": "One line for a recruiter.",
                    "model": "Client and study data stay on-machine unless I explicitly use a cloud fallback.",
                },
                {
                    "type": "mcq",
                    "q": "Who builds the MSSP platform vs separate marketing tools?",
                    "choices": [
                        "Same repo, same product",
                        "Jason builds Boundry Flask stack; partner tools are a different project",
                        "Outsourced team in India",
                        "Microsoft builds it",
                    ],
                    "answer_idx": 1,
                    "explain": "Boundry = this repo. Marketing GEO tools are not Boundry.",
                },
                {
                    "type": "mcq",
                    "q": "What should you NOT claim in a junior SOC interview?",
                    "choices": [
                        "I practiced SIEM triage on a lab stack I built",
                        "I operate a 24/7 staffed SOC with dozens of paying analysts",
                        "I use ticket dispositions and MITRE tags in practice",
                        "I hold ISC2 CC",
                    ],
                    "answer_idx": 1,
                    "explain": "Honest scale: portfolio lab plus certs, not fake enterprise ops.",
                },
            ],
        },
        {
            "id": "live",
            "name": "Live operations",
            "items": [
                {
                    "type": "mcq",
                    "q": "Main SIEM ingest sources in Boundry?",
                    "choices": [
                        "Twitter only",
                        "Windows events, firewall, syslog, app and VPN monitor",
                        "AWS keys from every client",
                        "Sentinel cloud only",
                    ],
                    "answer_idx": 1,
                    "explain": "siem_collector background threads plus Flask middleware.",
                },
                {
                    "type": "mcq",
                    "q": "Correct severity order (highest first)?",
                    "choices": [
                        "INFO, LOW, MEDIUM, HIGH, CRITICAL",
                        "CRITICAL, HIGH, MEDIUM, LOW, INFO",
                        "P1 to P5 only",
                        "HIGH only",
                    ],
                    "answer_idx": 1,
                    "explain": "Used in siem_events and UI coloring.",
                },
                {
                    "type": "flash",
                    "term": "Control Room",
                    "prompt": "What is it?",
                    "model": "Analyst HQ dashboard: VPN, clients, findings, links to SIEM and ops.",
                },
                {
                    "type": "mcq",
                    "q": "SPL-lite is:",
                    "choices": [
                        "Splunk Enterprise license",
                        "Subset of SPL parsed to SQLite over local events",
                        "Only KQL",
                        "Email phishing lab",
                    ],
                    "answer_idx": 1,
                    "explain": "spl_engine.py at /siem/query without requiring Splunk installed.",
                },
                {
                    "type": "mcq",
                    "q": "Unexpected VPN drop in Boundry?",
                    "choices": [
                        "Silent",
                        "CRITICAL or HIGH SIEM alert via vpn_monitor",
                        "Deletes database",
                        "Posts to LinkedIn",
                    ],
                    "answer_idx": 1,
                    "explain": "Reads local Nord state; no GUI connect API.",
                },
            ],
        },
        {
            "id": "mssp",
            "name": "MSSP workflow",
            "items": [
                {
                    "type": "mcq",
                    "q": "Ticket format:",
                    "choices": ["SN-1", "BT-2026-0042", "CVE-2024", "INC random UUID only"],
                    "answer_idx": 1,
                    "explain": "soc_cases ticket_no minted yearly.",
                },
                {
                    "type": "mcq",
                    "q": "Close disposition values:",
                    "choices": [
                        "red blue green",
                        "true_positive, false_positive, escalate",
                        "pass fail only",
                        "maybe unsure",
                    ],
                    "answer_idx": 1,
                    "explain": "Shift sim grades against expected_disposition.",
                },
                {
                    "type": "mcq",
                    "q": "Password spray pattern:",
                    "choices": [
                        "Many passwords on one user",
                        "One or few passwords tried on many accounts",
                        "UDP only",
                        "Only Linux",
                    ],
                    "answer_idx": 1,
                    "explain": "Spread failures to evade per-account lockout.",
                },
                {
                    "type": "flash",
                    "term": "Path A",
                    "prompt": "Agent skill meaning?",
                    "model": "Weekly SIEM monitoring report for retainer clients.",
                },
                {
                    "type": "mcq",
                    "q": "Practice tenant tags include:",
                    "choices": [
                        "Real client legal names",
                        "Contoso, NorthPeak, Harbor (fiction)",
                        "AWS account IDs",
                        "None",
                    ],
                    "answer_idx": 1,
                    "explain": "Multi-client queue without real tenant data.",
                },
            ],
        },
        {
            "id": "career",
            "name": "Career Hub",
            "items": [
                {
                    "type": "mcq",
                    "q": "Interview Gym progression:",
                    "choices": [
                        "Live only day one",
                        "Guided, then Coached, then Live",
                        "CISSP exam only",
                        "Prove it only",
                    ],
                    "answer_idx": 1,
                    "explain": "Six-step investigation skeleton with training wheels.",
                },
                {
                    "type": "mcq",
                    "q": "Hire labs include:",
                    "choices": [
                        "None",
                        "Email headers, EDR sim, KQL/SPL learn, intel stub, vuln queue",
                        "Production CrowdStrike",
                        "Exam dumps",
                    ],
                    "answer_idx": 1,
                    "explain": "soc-l1-skills-roadmap covered items.",
                },
                {
                    "type": "flash",
                    "term": "Live vs Practice",
                    "prompt": "SOC floor difference?",
                    "model": "Live uses real ingested events; Practice uses tagged soc_practice_events with SLA drills.",
                },
                {
                    "type": "mcq",
                    "q": "Security+ in Boundry is:",
                    "choices": [
                        "Brain dump",
                        "Original lessons; objectives as outline only",
                        "Only Messer verbatim text in git",
                        "Not present",
                    ],
                    "answer_idx": 1,
                    "explain": "PRD ethics: no dumps; private Messer layer optional.",
                },
            ],
        },
        {
            "id": "tech",
            "name": "Engineering",
            "items": [
                {
                    "type": "mcq",
                    "q": "AI policy:",
                    "choices": [
                        "Cloud first",
                        "Ollama local first; Anthropic fallback",
                        "No AI",
                        "Send all client data to Claude by default",
                    ],
                    "answer_idx": 1,
                    "explain": "cursorrules privacy rule.",
                },
                {
                    "type": "mcq",
                    "q": "Local database:",
                    "choices": [
                        "Mongo Atlas",
                        "SQLite; PostgreSQL if DATABASE_URL set",
                        "None",
                        "Excel",
                    ],
                    "answer_idx": 1,
                    "explain": "db_fetchone pattern with PH placeholder.",
                },
                {
                    "type": "flash",
                    "term": "bai",
                    "prompt": "What is it?",
                    "model": "PowerShell module for terminal API calls with X-Boundry-Token.",
                },
                {
                    "type": "mcq",
                    "q": "SOAR in Boundry:",
                    "choices": [
                        "Fully autonomous containment",
                        "Human approve gates on playbooks",
                        "Does not exist",
                        "Replaces SIEM",
                    ],
                    "answer_idx": 1,
                    "explain": "soar_engine approve flow.",
                },
            ],
        },
        {
            "id": "recruiter",
            "name": "Recruiter framing",
            "items": [
                {
                    "type": "mcq",
                    "q": "Resume line for Boundry:",
                    "choices": [
                        "CTO of national MSSP",
                        "Portfolio SOC lab: SIEM ingest, triage tickets, reporting",
                        "Invented MITRE",
                        "DoD clearance holder",
                    ],
                    "answer_idx": 1,
                    "explain": "Shipped practice stack beats inflated title.",
                },
                {
                    "type": "flash",
                    "term": "Credentials",
                    "prompt": "Say it honestly.",
                    "model": "ISC2 CC; York advanced cyber certificate path; Security+ in progress; CISSP only if passed.",
                },
                {
                    "type": "mcq",
                    "q": "Asked about Sentinel admin experience:",
                    "choices": [
                        "Lie about tenant work",
                        "Honest: local SIEM plus offline Sentinel-style and KQL labs",
                        "Refuse",
                        "Claim architect",
                    ],
                    "answer_idx": 1,
                    "explain": "Transfer mental models; label sims as practice.",
                },
                {
                    "type": "mcq",
                    "q": "Customer incident story you CAN tell:",
                    "choices": [
                        "Real client name and logs",
                        "Fictional spray alert walkthrough with ticket and client note",
                        "Made-up Fortune 500 breach you led",
                        "Internal secrets",
                    ],
                    "answer_idx": 1,
                    "explain": "Shift bank style narrative.",
                },
            ],
        },
    ],
}


INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#0a0e14">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="default">
<title>Boundry Pitch Quiz</title>
<link rel="manifest" href="__PITCH_BASE__manifest.webmanifest">
<link rel="apple-touch-icon" href="__PITCH_BASE__icon-192.png">
<style>
:root{--bg:#0a0e14;--card:#131d28;--border:#1e3045;--text:#cdd6e0;--dim:#7a9ab0;--accent:#00ff88;}
*{box-sizing:border-box}
body{margin:0;font-family:"Segoe UI",system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;padding:12px;padding-bottom:max(12px,env(safe-area-inset-bottom))}
h1{font-size:1.15rem;margin:0 0 4px;color:var(--accent)}
.sub{font-size:0.8rem;color:var(--dim);margin-bottom:12px}
.deck{display:block;width:100%;text-align:left;padding:12px 14px;margin-bottom:8px;background:var(--card);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:1rem;cursor:pointer}
.deck span{color:var(--dim);font-size:0.85rem}
.bar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}
.btn{padding:10px 14px;border-radius:8px;border:1px solid var(--border);background:var(--card);color:var(--text);font-size:0.95rem;cursor:pointer}
.btn.primary{border-color:var(--accent);color:var(--accent)}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px;margin-bottom:12px}
.q{font-size:1.05rem;line-height:1.4;margin-bottom:12px}
.choice{display:block;width:100%;text-align:left;padding:10px;margin:6px 0;background:#0f1923;border:1px solid var(--border);border-radius:6px;color:var(--text);cursor:pointer;font-size:0.95rem}
.choice.ok{border-color:var(--accent)}
.choice.bad{border-color:#ff4444}
.explain{margin-top:10px;font-size:0.9rem;color:var(--dim);line-height:1.45}
.flash-term{font-size:1.2rem;color:var(--accent);margin-bottom:8px}
.flash-prompt{color:var(--dim);margin-bottom:12px}
.flash-model{display:none;margin-top:12px;padding:12px;border-left:3px solid var(--accent);background:#0f1923}
.flash-model.show{display:block}
.stat{font-size:0.85rem;color:var(--dim)}
#screen-home{display:block}
#screen-quiz{display:none}
#screen-quiz.active{display:block}
</style>
</head>
<body>
<div id="screen-home" class="active">
  <h1 style="color:#00ff88">Boundry Pitch Quiz</h1>
  <p class="sub">Offline drill for recruiters and interviews. SMB security story. Progress stays on this phone.</p>
  <p class="stat" id="install-hint" style="color:#cdd6e0">Loading decks…</p>
  <div id="deck-list"></div>
</div>
<div id="screen-quiz">
  <div class="bar">
    <button type="button" class="btn" id="btn-back">Back</button>
    <button type="button" class="btn primary" id="btn-next">Next</button>
  </div>
  <p class="stat" id="progress"></p>
  <div class="card" id="quiz-card"></div>
</div>
<script src="__PITCH_BASE__quiz-data.js" defer></script>
<script src="__PITCH_BASE__app.js" defer></script>
</body>
</html>
""".replace("__PITCH_BASE__", PITCH_BASE)

APP_JS = r"""/* Boundry Pitch Quiz — client */
(function () {
  const STORAGE = "boundry_pitch_v1";
  function loadProgress() {
    try { return JSON.parse(localStorage.getItem(STORAGE) || "{}"); } catch (e) { return {}; }
  }
  function saveProgress(p) { localStorage.setItem(STORAGE, JSON.stringify(p)); }

  const deck = window.BOUNDRY_PITCH_DECK;
  const home = document.getElementById("screen-home");
  const quiz = document.getElementById("screen-quiz");
  const list = document.getElementById("deck-list");
  const card = document.getElementById("quiz-card");
  if (!deck || !deck.decks) {
    list.innerHTML =
      "<p class='stat' style='color:#ff8c00'>Quiz data did not load. On your phone use http://&lt;PC-LAN-IP&gt;:5000/pitch (same Wi-Fi). On the PC run: $env:FLASK_BIND_HOST = \\\"0.0.0.0\\\"; python app.py. Do not open the HTML file from disk.</p>";
    return;
  }

  let currentDeck = null;
  let items = [];
  let idx = 0;
  let prog = loadProgress();
  const progressEl = document.getElementById("progress");

  deck.decks.forEach(function (d) {
    const done = (prog[d.id] && prog[d.id].done) || 0;
    const b = document.createElement("button");
    b.type = "button";
    b.className = "deck";
    b.innerHTML = d.name + "<br><span>" + d.items.length + " cards · best " + done + "/" + d.items.length + "</span>";
    b.onclick = function () { startDeck(d); };
    list.appendChild(b);
  });

  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("__PITCH_BASE__sw.js").catch(function () {});
  }
  if (window.matchMedia("(display-mode: standalone)").matches) {
    document.getElementById("install-hint").textContent = "Installed. Works offline after first load.";
  } else {
    document.getElementById("install-hint").textContent =
      "Tip: open once on your PC URL, then Add to Home Screen (iPhone Share menu).";
  }

  document.getElementById("btn-back").onclick = function () {
    quiz.classList.remove("active");
    home.classList.add("active");
  };
  let score = 0;
  const btnNext = document.getElementById("btn-next");

  function onNext() {
    idx++;
    if (idx >= items.length) {
      const pct = Math.round(100 * score / items.length);
      prog[currentDeck.id] = { done: score, total: items.length, pct: pct, at: new Date().toISOString() };
      saveProgress(prog);
      card.innerHTML = "<p>Deck complete. Score " + score + "/" + items.length + " (" + pct + "%).</p>";
      btnNext.textContent = "Finish";
      btnNext.onclick = function () { location.reload(); };
      return;
    }
    renderItem();
  }
  btnNext.onclick = onNext;

  function startDeck(d) {
    currentDeck = d;
    items = d.items.slice().sort(function () { return Math.random() - 0.5; });
    idx = 0;
    score = 0;
    home.classList.remove("active");
    quiz.classList.add("active");
    btnNext.textContent = "Next";
    btnNext.onclick = onNext;
    renderItem();
  }

  function renderItem() {
    const it = items[idx];
    progressEl.textContent = (idx + 1) + " / " + items.length;
    card.innerHTML = "";
    if (it.type === "mcq") {
      const q = document.createElement("div");
      q.className = "q";
      q.textContent = it.q;
      card.appendChild(q);
      let answered = false;
      it.choices.forEach(function (c, i) {
        const b = document.createElement("button");
        b.type = "button";
        b.className = "choice";
        b.textContent = c;
        b.onclick = function () {
          if (answered) return;
          answered = true;
          if (i === it.answer_idx) {
            b.classList.add("ok");
            score++;
          } else {
            b.classList.add("bad");
          }
          const ex = document.createElement("div");
          ex.className = "explain";
          ex.textContent = it.explain || "";
          card.appendChild(ex);
        };
        card.appendChild(b);
      });
    } else {
      const t = document.createElement("div");
      t.className = "flash-term";
      t.textContent = it.term || "Term";
      card.appendChild(t);
      const p = document.createElement("div");
      p.className = "flash-prompt";
      p.textContent = it.prompt || "Say it out loud.";
      card.appendChild(p);
      const m = document.createElement("div");
      m.className = "flash-model";
      m.textContent = it.model || "";
      card.appendChild(m);
      const rev = document.createElement("button");
      rev.type = "button";
      rev.className = "btn primary";
      rev.textContent = "Show model answer";
      rev.onclick = function () {
        m.classList.add("show");
        score++;
      };
      card.appendChild(rev);
    }
  }
})();
"""

SW_JS = r"""const CACHE = "boundry-pitch-v3";
const BASE = "__PITCH_BASE__";
const ASSETS = [
  BASE + "index.html",
  BASE + "app.js",
  BASE + "quiz-data.js",
  BASE + "manifest.webmanifest",
  BASE + "icon-192.png",
];
self.addEventListener("install", (e) => {
  e.waitUntil(
    caches.open(CACHE).then((c) => c.addAll(ASSETS).catch(() => null)).then(() => self.skipWaiting())
  );
});
self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});
self.addEventListener("fetch", (e) => {
  if (e.request.method !== "GET") return;
  e.respondWith(
    caches.match(e.request).then((r) => {
      if (r) return r;
      return fetch(e.request).catch(() => caches.match(BASE + "index.html"));
    })
  );
});
"""

MANIFEST = {
    "name": "Boundry Pitch Quiz",
    "short_name": "Boundry Quiz",
    "description": "Offline Boundry.AI pitch and platform literacy drill",
    "start_url": PITCH_BASE + "index.html",
    "scope": PITCH_BASE,
    "display": "standalone",
    "background_color": "#0a0e14",
    "theme_color": "#0a0e14",
    "icons": [
        {"src": "icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any"},
    ],
}

DOCS = """# Boundry Pitch Quiz (offline PWA)

Phone drill for explaining Boundry.AI to recruiters and hiring managers.

## Open

1. On the PC (PowerShell), bind Flask to the LAN (once per session):

```powershell
$env:FLASK_BIND_HOST = "0.0.0.0"
python app.py
```

Or run `tools/enable_home_lan_flask.ps1` if you use that helper.

2. On your phone (same Wi-Fi as the PC): `http://<PC-LAN-IP>:5000/pitch`
   (Example: `http://10.0.0.2:5000/pitch`). **Do not** use `localhost` on the phone.
3. **iPhone:** Share → Add to Home Screen.
4. Open once online so the service worker caches files. Then works offline.

## Not loading?

- Phone cannot reach `127.0.0.1` — that is the PC only. Use the LAN IP.
- If you see the title but no deck buttons, `quiz-data.js` failed. Hard refresh or clear Safari site data for that host.
- Opening `index.html` from File Explorer (`file://`) will not work.
- Windows Firewall may block port 5000 on Private network the first time Flask listens on `0.0.0.0`.

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
"""


def write_quiz_data_js() -> None:
    deck_doc = merge_decks(DECK)
    lines = ["/* Boundry Pitch Quiz — golden + data/boundry_pitch/generated_items.json */", "window.BOUNDRY_PITCH_DECK = "]
    lines.append(json.dumps(deck_doc, indent=2))
    lines.append(";")
    (OUT / "quiz-data.js").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_icon_placeholder() -> None:
    """Minimal valid 192x192 PNG (solid #00ff88 on #0a0e14) via png bytes or skip."""
    # Smallest approach: 1x1 png expanded - iOS wants apple-touch-icon; use data URI in HTML if missing
    # Write a tiny PNG (68 bytes grey) so manifest validates
    png = bytes.fromhex(
        "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
        "0000000a49444154789c6360000002000005aa0dc46b0000000049454e44ae426082"
    )
    (OUT / "icon-192.png").write_bytes(png)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    write_quiz_data_js()
    (OUT / "index.html").write_text(INDEX_HTML, encoding="utf-8")
    (OUT / "app.js").write_text(APP_JS.replace("__PITCH_BASE__", PITCH_BASE), encoding="utf-8")
    (OUT / "sw.js").write_text(SW_JS.replace("__PITCH_BASE__", PITCH_BASE), encoding="utf-8")
    (OUT / "manifest.webmanifest").write_text(json.dumps(MANIFEST, indent=2), encoding="utf-8")
    write_icon_placeholder()
    (ROOT / "docs" / "BOUNDRY_PITCH_PWA.md").write_text(DOCS, encoding="utf-8")
    merged = merge_decks(DECK)
    n = sum(len(d["items"]) for d in merged["decks"])
    print(f"Wrote PWA to {OUT} ({len(merged['decks'])} decks, {n} items)")


if __name__ == "__main__":
    main()