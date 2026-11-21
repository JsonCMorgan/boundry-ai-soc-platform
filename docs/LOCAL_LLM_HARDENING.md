# Local LLM hardening (Boundry stack)

Based on [Your Local AI Is Not as Private as You Think](https://youtu.be/3mx84MRj8lY) (Kai, Oct 2026). **Privacy ≠ safety:** local weights can still drive tools that read `.env`, run shell, or call the network.

**Your stack:** Ollama `:11434` → Flask `:5000` + Open WebUI `:8080` (tools enabled). Highest risk = **Open WebUI + tools** + secrets in `C:\Dev\MSSP`.

---

## Recorded baseline (audit on implement)

| Component | Version / bind |
|-----------|----------------|
| Ollama | 0.40.8 (≥ 0.17.1 Bleeding Llama fix; keep updating from [ollama.com](https://ollama.com)) |
| Open WebUI | 0.9.5 (`pip install -U open-webui`) |
| Listen | `127.0.0.1` on 11434, 8080, 5000 (loopback OK) |
| `OLLAMA_HOST` | Unset (defaults to loopback) |

Re-run audit anytime:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Dev\MSSP\tools\audit_local_llm.ps1
```

---

## Five video fixes → Boundry

### 1. Loopback + auth

- Launcher sets `OLLAMA_HOST=127.0.0.1` before `ollama serve` ([launch-boundry-ai.bat](C:\Dev\launch-boundry-ai.bat)).
- Open WebUI: `--host 127.0.0.1 --port 8080` only.
- **Firewall (Administrator once):** double-click [tools/run_harden_ports_elevated.bat](../tools/run_harden_ports_elevated.bat) (UAC) or run [_harden_ports_option_a.ps1](../tools/_harden_ports_option_a.ps1) from an **elevated** PowerShell. Blocks inbound **11434, 8080, 5000** (+ SMB/RPC). A normal terminal gets `Access is denied` on `Set-NetFirewallRule`; that is expected.
- Remote access later: **Tailscale** or authenticated reverse proxy — never `OLLAMA_HOST=0.0.0.0`.

### 2. Update runners

- Ollama: official Windows app / installer only (no fake GitHub Pages DMGs).
- `pip install -U open-webui`
- After updates, restart stack via launch bat.

### 3. Official models for tools

Current `ollama list` (official library tags): `llama3.1:8b`, `qwen2.5-coder:7b`, `deepseek-r1:8b`, `qwen2.5-coder:1.5b-base`, `nomic-embed-text`.

- **Tool allowlist:** [tools/ollama_tool_allowlist.txt](../tools/ollama_tool_allowlist.txt)
- Do **not** use abliterated / viral HF merges with tools enabled.
- **Embeddings:** `nomic-embed-text` — chat/tools only if you understand exposure; prefer not attaching tools to embed models.

Remove untrusted models:

```powershell
ollama rm <model-name>
```

### 4. Secrets outside MSSP tree

- Store secrets in **`%USERPROFILE%\.boundry\secrets.env`** (template: [tools/boundry_secrets.env.example](../tools/boundry_secrets.env.example)).
- Migrate from repo `.env` once, then trim repo copy:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Dev\MSSP\tools\migrate_secrets_to_boundry_home.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Dev\MSSP\tools\trim_mssp_dotenv.ps1
```

- Launcher loads via [tools/load_boundry_secrets.ps1](../tools/load_boundry_secrets.ps1) → `%USERPROFILE%\.boundry\_runtime_env.bat`.
- Minimize API keys in the **Ollama process** environment (memory disclosure class of bugs).
- Cursor: [.cursorignore](../.cursorignore) hides `.env`, tokens, private study packs.

### 5. Split command power from network (Open WebUI)

Do in **Admin UI** (http://127.0.0.1:8080):

1. **Authentication**
   - Admin → Settings → **Authentication**: enable.
   - Disable public sign-up; use a single admin account.
   - Require login before chat and tools.

2. **Tools / functions**
   - Admin → **Tools** / **Functions**: disable shell, arbitrary filesystem, or HTTP tools you do not need.
   - Do not point workspace roots at `C:\Dev\MSSP` or `%USERPROFILE%\.boundry`.
   - Use tool-capable models **only** from [ollama_tool_allowlist.txt](../tools/ollama_tool_allowlist.txt).
   - Prefer a **chat-only** model profile for experimenting with unknown prompts.

3. **Plugins**
   - Remove or disable plugins that add exec, file, or outbound network without review.

Flask `/run-agent` stays **Ollama-first**, localhost-only; no cloud fallback unless you explicitly set keys.

---

## Weekly habit (automated)

**Register once** (Sunday 10:00 AM audit + log under `tools/_audit_local_llm_*.txt`):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Dev\MSSP\tools\register_llm_audit_scheduler.ps1
```

**After `ollama pull`** (pull + audit in one step):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Dev\MSSP\tools\ollama_pull_audit.ps1 qwen2.5-coder:7b
```

**After Open WebUI / pip upgrade** (or major plugin changes):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Dev\MSSP\tools\open_webui_upgrade_audit.ps1
```

Manual anytime:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Dev\MSSP\tools\audit_local_llm.ps1
```

Also: confirm no new listen on `0.0.0.0`; do not paste stranger test prompts into tool-enabled chats.

---

## Related docs

- [PRE_CLIENT_HARDENING.md](PRE_CLIENT_HARDENING.md) — M9 local LLM
- [PRIVACY_DATA_HANDLING.md](PRIVACY_DATA_HANDLING.md) — Ollama-first ops data
- [RAILWAY_SECRET_ROTATION.md](RAILWAY_SECRET_ROTATION.md) — cloud deploy (if reused later)

*Boundry.AI · Jason Morgan*
