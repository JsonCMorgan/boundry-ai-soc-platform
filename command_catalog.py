"""
Analyst command reference — single source for /ops/commands dashboard and API.
"""

from __future__ import annotations

from typing import Any, TypedDict


class CommandCategory(TypedDict):
    id: str
    title: str
    subtitle: str
    accent: str


class CommandRow(TypedDict, total=False):
    id: str
    category: str
    kind: str
    name: str
    command: str
    summary: str
    detail: str
    href: str
    tags: list[str]


CATEGORIES: list[CommandCategory] = [
    {
        "id": "stack",
        "title": "Stack & launcher",
        "subtitle": "Start Boundry, secrets, and local services",
        "accent": "#00ff88",
    },
    {
        "id": "llm",
        "title": "Local LLM & MCP",
        "subtitle": "Ollama routing, Cursor MCP, audits",
        "accent": "#9944ee",
    },
    {
        "id": "bai",
        "title": "bai terminal",
        "subtitle": "PowerShell module talking to Flask terminal API",
        "accent": "#00d4ff",
    },
    {
        "id": "live",
        "title": "Live ops (browser)",
        "subtitle": "Analyst dashboards and APIs",
        "accent": "#00b432",
    },
    {
        "id": "career",
        "title": "Career & study",
        "subtitle": "Cert labs, drills, interview gym",
        "accent": "#2dd4bf",
    },
    {
        "id": "dev",
        "title": "Dev & CI",
        "subtitle": "Tests, linters, content pipelines",
        "accent": "#ffcc00",
    },
    {
        "id": "docs",
        "title": "Docs on disk",
        "subtitle": "Markdown references (open in editor)",
        "accent": "#7a9ab0",
    },
]

# kind: shell | powershell | bai | mcp | url | python
_ROWS: list[CommandRow] = [
    # --- stack ---
    {
        "id": "launch-stack",
        "category": "stack",
        "kind": "shell",
        "name": "Launch full stack",
        "command": r"C:\Dev\launch-boundry-ai.bat",
        "summary": "Ollama (127.0.0.1), secrets, Flask :5000, Open WebUI :8080.",
        "detail": "Loads %USERPROFILE%\\.boundry\\secrets.env before Flask starts.",
        "tags": ["ollama", "flask", "startup"],
    },
    {
        "id": "load-secrets",
        "category": "stack",
        "kind": "powershell",
        "name": "Load secrets (manual)",
        "command": r"powershell -NoProfile -ExecutionPolicy Bypass -File C:\Dev\MSSP\tools\load_boundry_secrets.ps1",
        "summary": "Hydrates env from ~/.boundry/secrets.env (not stored in repo).",
        "tags": ["secrets", "env"],
    },
    {
        "id": "migrate-secrets",
        "category": "stack",
        "kind": "powershell",
        "name": "Migrate secrets out of repo",
        "command": r"powershell -NoProfile -ExecutionPolicy Bypass -File C:\Dev\MSSP\tools\migrate_secrets_to_boundry_home.ps1",
        "summary": "One-time move from MSSP .env to user profile .boundry.",
        "tags": ["secrets"],
    },
    {
        "id": "harden-ports",
        "category": "stack",
        "kind": "shell",
        "name": "Harden inbound ports (elevated)",
        "command": r"C:\Dev\MSSP\tools\run_harden_ports_elevated.bat",
        "summary": "Firewall block on 11434, 8080, 5000 (+ SMB/RPC). Requires UAC.",
        "tags": ["firewall", "hardening"],
    },
    # --- llm ---
    {
        "id": "audit-llm",
        "category": "llm",
        "kind": "powershell",
        "name": "Local LLM audit",
        "command": r"powershell -NoProfile -ExecutionPolicy Bypass -File C:\Dev\MSSP\tools\audit_local_llm.ps1",
        "summary": "Loopback bind, OLLAMA_HOST, model list, Open WebUI hints.",
        "href": "/docs/LOCAL_LLM_HARDENING.md",
        "tags": ["ollama", "audit"],
    },
    {
        "id": "ollama-pull-audit",
        "category": "llm",
        "kind": "powershell",
        "name": "Pull model + audit",
        "command": r"powershell -NoProfile -ExecutionPolicy Bypass -File C:\Dev\MSSP\tools\ollama_pull_audit.ps1 qwen2.5-coder:7b",
        "summary": "Run after ollama pull; writes tools\\_audit_local_llm_*.txt.",
        "tags": ["ollama"],
    },
    {
        "id": "setup-cursor-mcp",
        "category": "llm",
        "kind": "powershell",
        "name": "Register Boundry MCP in Cursor",
        "command": r"powershell -NoProfile -ExecutionPolicy Bypass -File C:\Dev\MSSP\tools\setup_cursor_boundry_mcp.ps1",
        "summary": "Writes ~/.cursor/mcp.json for boundry-ai server.",
        "detail": "Restart Cursor; enable boundry-ai under MCP settings.",
        "href": "/docs/LLM_ROUTING_WORKFLOW.md",
        "tags": ["cursor", "mcp"],
    },
    {
        "id": "mcp-plan",
        "category": "llm",
        "kind": "mcp",
        "name": "boundry_plan",
        "command": "boundry_plan(task=…, spec_path=docs/handoffs/…)",
        "summary": "DeepSeek R1 on loopback — implementation spec before coding.",
        "detail": "Use in Cursor chat when MCP boundry-ai is enabled.",
        "tags": ["mcp", "deepseek"],
    },
    {
        "id": "mcp-implement",
        "category": "llm",
        "kind": "mcp",
        "name": "boundry_implement",
        "command": "boundry_implement(task=…, context_paths=[app.py, …])",
        "summary": "Qwen Coder draft diffs; Composer applies + pytest.",
        "tags": ["mcp", "qwen"],
    },
    {
        "id": "mcp-tutor",
        "category": "llm",
        "kind": "mcp",
        "name": "boundry_tutor",
        "command": "boundry_tutor(question=…)",
        "summary": "Llama 8B tutor voice — concepts, no file reads.",
        "tags": ["mcp", "study"],
    },
    {
        "id": "mcp-threats",
        "category": "llm",
        "kind": "mcp",
        "name": "get_recent_threats",
        "command": "get_recent_threats(hours=24, severity=ALL)",
        "summary": "Recent threat reports from app.db (MCP security tools).",
        "tags": ["mcp", "siem"],
    },
    {
        "id": "mcp-vt-ip",
        "category": "llm",
        "kind": "mcp",
        "name": "lookup_ip_reputation",
        "command": "lookup_ip_reputation(ip=1.2.3.4)",
        "summary": "VirusTotal IP check (needs VIRUSTOTAL_API_KEY in env).",
        "tags": ["mcp", "intel"],
    },
    # --- bai ---
    {
        "id": "bai-status",
        "category": "bai",
        "kind": "bai",
        "name": "bai status",
        "command": "bai status",
        "summary": "VPN, findings count, XP, stack health via terminal token.",
        "tags": ["terminal"],
    },
    {
        "id": "bai-scan",
        "category": "bai",
        "kind": "bai",
        "name": "bai scan",
        "command": "bai scan",
        "summary": "Trigger machine security audit from PowerShell.",
        "tags": ["scanner"],
    },
    {
        "id": "bai-findings",
        "category": "bai",
        "kind": "bai",
        "name": "bai findings",
        "command": "bai findings",
        "summary": "List open system_findings from terminal.",
        "tags": ["triage"],
    },
    {
        "id": "bai-resolve",
        "category": "bai",
        "kind": "bai",
        "name": "bai resolve <id>",
        "command": "bai resolve 42",
        "summary": "Mark finding resolved + award XP when applicable.",
        "tags": ["triage"],
    },
    {
        "id": "bai-xp",
        "category": "bai",
        "kind": "bai",
        "name": "bai xp",
        "command": "bai xp system_scan",
        "summary": "Manual XP award (uses token auth, not browser session).",
        "tags": ["gamification"],
    },
    {
        "id": "bai-help",
        "category": "bai",
        "kind": "bai",
        "name": "bai help",
        "command": "bai help",
        "summary": "List all bai subcommands.",
        "tags": ["terminal"],
    },
    # --- live ops urls ---
    {
        "id": "url-control-room",
        "category": "live",
        "kind": "url",
        "name": "Control Room",
        "command": "/control-room",
        "summary": "Analyst HQ — clients, reports, quick actions.",
        "href": "/control-room",
        "tags": ["dashboard"],
    },
    {
        "id": "url-siem",
        "category": "live",
        "kind": "url",
        "name": "SIEM live stream",
        "command": "/siem",
        "summary": "Ingested events, rules, correlation.",
        "href": "/siem",
        "tags": ["siem"],
    },
    {
        "id": "url-spl",
        "category": "live",
        "kind": "url",
        "name": "SPL query",
        "command": "/siem/query",
        "summary": "SPL-lite → SQLite query UI.",
        "href": "/siem/query",
        "tags": ["spl"],
    },
    {
        "id": "url-soc",
        "category": "live",
        "kind": "url",
        "name": "SOC floor",
        "command": "/soc",
        "summary": "Cases, tickets, shift workflow.",
        "href": "/soc",
        "tags": ["soc"],
    },
    {
        "id": "url-mission",
        "category": "live",
        "kind": "url",
        "name": "Mission Control queue",
        "command": "/soc/mission",
        "summary": "Unified triage: findings + cases + SOAR.",
        "href": "/soc/mission",
        "tags": ["triage"],
    },
    {
        "id": "url-soar",
        "category": "live",
        "kind": "url",
        "name": "SOAR",
        "command": "/soar",
        "summary": "Playbook incidents and automation chain.",
        "href": "/soar",
        "tags": ["soar"],
    },
    {
        "id": "api-vpn",
        "category": "live",
        "kind": "url",
        "name": "VPN status API",
        "command": "GET /api/vpn/status",
        "summary": "NordVPN monitor state (JSON).",
        "tags": ["api", "vpn"],
    },
    {
        "id": "api-spl",
        "category": "live",
        "kind": "url",
        "name": "SPL API",
        "command": "GET /api/siem/spl?q=source=firewall | head 20",
        "summary": "Programmatic SPL-lite queries.",
        "tags": ["api", "spl"],
    },
    {
        "id": "url-commands",
        "category": "live",
        "kind": "url",
        "name": "Command Center (this page)",
        "command": "/ops/commands",
        "summary": "Searchable catalog of commands and routes.",
        "href": "/ops/commands",
        "tags": ["meta"],
    },
    # --- career ---
    {
        "id": "url-career",
        "category": "career",
        "kind": "url",
        "name": "Career Lab hub",
        "command": "/career",
        "summary": "Index of hire-aligned labs and drills.",
        "href": "/career",
        "tags": ["career"],
    },
    {
        "id": "url-secplus",
        "category": "career",
        "kind": "url",
        "name": "Security+ Lab",
        "command": "/career/secplus",
        "summary": "Lessons, quizzes, Messer layer when enabled.",
        "href": "/career/secplus",
        "tags": ["secplus"],
    },
    {
        "id": "url-review",
        "category": "career",
        "kind": "url",
        "name": "Daily review queue",
        "command": "/career/review",
        "summary": "Spaced retention / Help-me wrong answers.",
        "href": "/career/review",
        "tags": ["retention"],
    },
    {
        "id": "url-interview",
        "category": "career",
        "kind": "url",
        "name": "Interview Gym",
        "command": "/career/interview",
        "summary": "Scenario prompts with local AI coach.",
        "href": "/career/interview",
        "tags": ["interview"],
    },
    {
        "id": "url-cissp",
        "category": "career",
        "kind": "url",
        "name": "CISSP hub",
        "command": "/cissp",
        "summary": "Eight-domain study grid + practice.",
        "href": "/cissp",
        "tags": ["cissp"],
    },
    # --- dev ---
    {
        "id": "pytest-all",
        "category": "dev",
        "kind": "shell",
        "name": "Run test suite",
        "command": r"cd C:\Dev\MSSP && pytest -q",
        "summary": "Full regression (SQLite test client).",
        "tags": ["ci", "pytest"],
    },
    {
        "id": "pytest-one",
        "category": "dev",
        "kind": "shell",
        "name": "Run one test file",
        "command": r"cd C:\Dev\MSSP && pytest -q tests/test_regressions.py",
        "summary": "Fast scope when touching app.py / soc_lab.",
        "tags": ["pytest"],
    },
    {
        "id": "ruff",
        "category": "dev",
        "kind": "shell",
        "name": "Ruff lint",
        "command": r"cd C:\Dev\MSSP && ruff check app.py",
        "summary": "Quick static check on the monolith.",
        "tags": ["lint"],
    },
    {
        "id": "messer-quiz-batch",
        "category": "dev",
        "kind": "python",
        "name": "Messer notes quiz batch",
        "command": r"python C:\Dev\MSSP\tools\messer_notes_quiz_batch.py --help",
        "summary": "Generate or audit notes-driven quizzes (Ollama).",
        "tags": ["messer", "ollama"],
    },
    {
        "id": "git-push-rule",
        "category": "dev",
        "kind": "shell",
        "name": "Git push (human confirm)",
        "command": "git push",
        "summary": "Agents ask Jason before any push (.cursor/rules/git-push-confirm).",
        "detail": "Commit locally anytime; push only after explicit yes.",
        "tags": ["git"],
    },
    # --- docs ---
    {
        "id": "doc-prd",
        "category": "docs",
        "kind": "shell",
        "name": "Product PRD",
        "command": r"C:\Dev\MSSP\docs\PRD.md",
        "summary": "Must / Won't product truth.",
        "tags": ["docs"],
    },
    {
        "id": "doc-plan",
        "category": "docs",
        "kind": "shell",
        "name": "Implementation plan",
        "command": r"C:\Dev\MSSP\docs\IMPLEMENTATION_PLAN.md",
        "summary": "Stage checklist and shipped items.",
        "tags": ["docs"],
    },
    {
        "id": "doc-llm-workflow",
        "category": "docs",
        "kind": "shell",
        "name": "LLM routing workflow",
        "command": r"C:\Dev\MSSP\docs\LLM_ROUTING_WORKFLOW.md",
        "summary": "Plan → implement → Composer review loop.",
        "tags": ["llm"],
    },
    {
        "id": "doc-llm-security",
        "category": "docs",
        "kind": "shell",
        "name": "LLM MCP security",
        "command": r"C:\Dev\MSSP\docs\LLM_MCP_SECURITY.md",
        "summary": "Loopback, redaction, tool power model.",
        "tags": ["llm", "security"],
    },
    {
        "id": "doc-spec-template",
        "category": "docs",
        "kind": "shell",
        "name": "Handoff SPEC template",
        "command": r"C:\Dev\MSSP\docs\handoffs\SPEC-template.md",
        "summary": "Copy before boundry_plan / implement.",
        "tags": ["handoff"],
    },
]


def command_catalog() -> dict[str, Any]:
    """Return categories + rows for templates and JSON API."""
    return {
        "categories": CATEGORIES,
        "commands": list(_ROWS),
        "kinds": {
            "shell": "Windows cmd / PowerShell one-liner",
            "powershell": "PowerShell script",
            "bai": "BoundryAI PowerShell module",
            "mcp": "Cursor / Claude MCP tool name",
            "url": "In-app route or HTTP API",
            "python": "Python CLI in tools/",
        },
    }


def commands_for_category(category_id: str) -> list[CommandRow]:
    """Filter commands by category id."""
    return [r for r in _ROWS if r.get("category") == category_id]