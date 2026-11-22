# LLM routing workflow (Cursor MCP + local Ollama)

Integrated flow so **Composer** stays review/test/git; **Ollama on loopback** does plan, code drafts, and tutoring.

## Architecture

```text
Cursor (Composer) ── MCP stdio ── boundry-mcp-server (server.py)
                                      │
                    ┌─────────────────┼─────────────────┐
                    ▼                 ▼                 ▼
            boundry_plan      boundry_implement   boundry_tutor
            deepseek-r1:8b    qwen2.5-coder:7b    llama3.1:8b
                    │                 │                 │
                    └──────── 127.0.0.1:11434 ─────────┘
```

GSN Offline stays **outside** this path (manual only). Official weights run through Ollama.

## One-time setup

1. Start stack: `C:\Dev\launch-boundry-ai.bat` (Ollama on `127.0.0.1`).
2. Register MCP in Cursor:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Dev\MSSP\tools\setup_cursor_boundry_mcp.ps1
```

3. **Cursor → Settings → MCP** → enable **boundry-ai** → restart Cursor.
4. Optional keys for VT/Shodan tools only: set in user env, not in `mcp.json`.

## Auto-triage in Cursor

Project rule `.cursor/rules/llm-mcp-auto-triage.mdc` tells the agent to decide each turn whether `boundry_plan`, `boundry_implement`, or `boundry_tutor` beats Composer-only work. You can still say **"no MCP"** or **"use the loop"** to steer.

## Daily loop

| Step | Who | Action |
|------|-----|--------|
| 1 | You in chat | "Plan: add X" → Composer calls `boundry_plan` |
| 2 | MCP | R1 spec returned in chat |
| 3 | You | Save spec to `docs/handoffs/SPEC-YYYY-MM-DD-topic.md` (optional) |
| 4 | Composer | `boundry_implement` with `task` + `spec_path` + `context_paths` |
| 5 | Composer | Apply diff, `pytest`, ruff on touched paths |
| 6 | You | Commit; ask Composer to push only when you confirm |

Study questions: `boundry_tutor` (no file reads).

## MCP tools

| Tool | Model | Reads files? |
|------|-------|----------------|
| `boundry_plan` | `deepseek-r1:8b` | Optional spec under repo |
| `boundry_implement` | `qwen2.5-coder:7b` | Spec + up to 5 context paths |
| `boundry_tutor` | `llama3.1:8b` | No |

Security details: [LLM_MCP_SECURITY.md](./LLM_MCP_SECURITY.md).

## Spec template

Copy [handoffs/SPEC-template.md](./handoffs/SPEC-template.md) when starting a feature.

## Overrides

| Env | Purpose |
|-----|---------|
| `OLLAMA_BASE_URL` | Default `http://127.0.0.1:11434` (loopback only) |
| `BOUNDRY_MSSP_ROOT` | Default `C:\Dev\MSSP` |
| `OLLAMA_MODEL_PLAN` / `_IMPLEMENT` / `_TUTOR` | Override role models (must be on allowlist) |

Allowlist: [tools/ollama_tool_allowlist.txt](../tools/ollama_tool_allowlist.txt).

## Command dashboard (browser)

After login: **http://localhost:5000/ops/commands** (Operations → Command Center). Search MCP, bai, scripts, and routes in one place.

## Where it lives in your code

| Piece | Path |
|-------|------|
| MCP server | `C:\Dev\boundry-mcp-server\server.py` |
| Ollama router + guards | `C:\Dev\boundry-mcp-server\ollama_router.py` |
| Cursor MCP installer | `C:\Dev\MSSP\tools\setup_cursor_boundry_mcp.ps1` |
| In-app Ollama (Flask) | `app.py` (`OLLAMA_BASE_URL`) |
| Hardening baseline | `docs/LOCAL_LLM_HARDENING.md` |