# Why MCP + tools needs a security review (Boundry)

This doc explains the warning: **"MCP + tools = security review; keep loopback and no secrets in prompts."**

## Short answer

**MCP (Model Context Protocol)** lets the AI in Cursor **call programs on your PC** (tools). Each tool is a small API: read files, query SQLite, call Ollama, hit VirusTotal. That is powerful and **not the same as chat**. If a tool can reach secrets, the network, or arbitrary paths, a bad prompt or a confused model can **leak or misuse** them.

**Loopback** means Ollama and Flask listen only on `127.0.0.1`, so other machines on the LAN cannot drive your LLM. **No secrets in prompts** means anything you send to Ollama is **model context** (RAM, logs, future bugs). We redact and block sensitive files so client keys never ride along with a plan/code request.

## Analogy

MCP tools are like giving a junior analyst **badges**: SIEM read, file share, terminal. You decide which doors each badge opens. **Loopback** is keeping the SOC room **inside the building**. **Redaction** is **stripping sticky notes with passwords** off the ticket before you hand it to the trainee.

## What we built for Option C

| Control | What it does |
|---------|----------------|
| Loopback-only Ollama URL | `ollama_router.py` rejects non-`127.0.0.1` / `localhost` hosts |
| Model allowlist | Only tags in `tools/ollama_tool_allowlist.txt` |
| Path jail | Reads only under `BOUNDRY_MSSP_ROOT`; deny `.env`, `app.db`, `.boundry`, `private`, etc. |
| Redaction | Strips common `KEY=`, Stripe `sk-`, Slack `xoxb-`, named env patterns |
| Text-only implement | `boundry_implement` returns diffs in chat; **no** auto-write or shell |
| Size caps | Truncate huge files so one call cannot dump the whole repo |

## What MCP does **not** automatically protect

| Risk | Why it matters |
|------|----------------|
| **You paste a secret into chat** | Cursor cloud may see chat; Ollama sees tutor/plan text. Do not paste `.env` lines. |
| **VirusTotal / Shodan tools** | Those send **IPs and hashes** to the internet by design. Fine for threat work; not for client PII dumps. |
| **Composer still edits files** | After Qwen drafts code, Composer applies changes. That is intended; review diffs like any PR. |
| **Open WebUI with tools** | Separate surface from MCP. Harden per `LOCAL_LLM_HARDENING.md` (auth, disable exec tools). |
| **Malformed cloud MCP** | Remote MCP servers are third parties. Boundry LLM tools are **local stdio only**. |

## "Security review" in practice (5 minutes, repeat when you add tools)

1. **Loopback:** `audit_local_llm.ps1` shows `127.0.0.1` on 11434 / 5000 / 8080.
2. **Allowlist:** `ollama list` matches `ollama_tool_allowlist.txt` (no random HF merges).
3. **Secrets location:** `%USERPROFILE%\.boundry\secrets.env`, not in repo prompts.
4. **New tool checklist:** Does it write disk? Run shell? Call non-loopback URLs? Read paths outside MSSP?
5. **VT/Shodan keys:** User env only; never commit to `mcp.json`.

## Interview line

"I route planning and codegen through a local MCP server that only talks to loopback Ollama, allowlists models, jails file reads to the repo, and redacts secrets before they hit the model. Cloud Cursor is for review and tests, not for holding client credentials in prompts."

## Where it lives

- Router guards: `C:\Dev\boundry-mcp-server\ollama_router.py`
- Tool registration: `C:\Dev\boundry-mcp-server\server.py`
- Stack hardening: `docs/LOCAL_LLM_HARDENING.md`
- Workflow: `docs/LLM_ROUTING_WORKFLOW.md`