# MCP Setup — Boundry.AI

Practical MCP wiring for Jason Morgan's Boundry.AI agent operations. Placeholders only — **never commit real keys**.

---

## Overview

| MCP | Purpose for Boundry.AI | Status |
|-----|------------------------|--------|
| **Stripe** | Monthly SIEM retainer invoicing | Jason must OAuth or add restricted key |
| **Notion** | Client CRM, task tracking | May already be in workspace |
| **Slack** | CRITICAL finding alerts | Jason must add bot token |
| **Cloudflare MCP Portals** | Multi-client MCP gateway (scale phase) | Optional — Zero Trust setup |

Skills reference these in: `weekly_siem_report_skill.md` (Stripe), `new_finding_triage_skill.md` (Slack).

---

## Config file location

Cursor reads MCP config from:

- **User-level:** `~/.cursor/mcp.json` (Windows: `C:\Users\<you>\.cursor\mcp.json`)
- **Project-level:** `.cursor/mcp.json` in repo (optional, team-shared structure without secrets)

---

## Stripe MCP

**Docs:** https://docs.stripe.com/mcp

### Option A — Remote server (OAuth, recommended)

```json
{
  "mcpServers": {
    "stripe": {
      "url": "https://mcp.stripe.com"
    }
  }
}
```

After adding, restart Cursor. First use opens Stripe OAuth consent. Manage sessions in Stripe Dashboard → User settings → OAuth sessions.

### Option B — Local npx server (restricted key)

```json
{
  "mcpServers": {
    "stripe": {
      "command": "npx",
      "args": ["-y", "@stripe/mcp@latest"],
      "env": {
        "STRIPE_SECRET_KEY": "rk_test_YOUR_RESTRICTED_KEY_HERE"
      }
    }
  }
}
```

Use **restricted keys** scoped to: Customers (read/write), Invoices (read/write), Subscriptions (read/write), Products/Prices (read).

### Official tools (weekly report + onboarding)

| Tool | Use |
|------|-----|
| `list_customers` | Find client by email |
| `create_customer` | New onboarding |
| `list_products` / `create_product` | SIEM Monitoring SKU |
| `list_prices` / `create_price` | Monthly retainer price |
| `list_subscriptions` | Verify active billing |
| `create_invoice` | One-time audit invoice |
| `create_invoice_item` | Line items |
| `finalize_invoice` | Send invoice |
| `list_invoices` | Reconciliation |
| `search_stripe_resources` | Cross-object search |

### Example prompts (Jason runs in Cursor chat)

> Using Stripe MCP, list customers with email containing `greenleaf`. Show active subscriptions.

> Create a draft invoice for customer `cus_XXX` for Boundry.AI SIEM Monitoring — $499/month. Do not finalize until I confirm.

> Search Stripe docs for recurring subscription best practices with metadata.

### Manual until connected

Skills mark Stripe steps as **BLOCKED** until OAuth completes. Jason uses Stripe Dashboard directly and records customer/subscription IDs in progress files.

---

## Notion MCP

**Plugin:** Notion workspace plugin (already available in Cursor if enabled).

### Use for Boundry.AI

- **Client CRM database:** company, contact, scope, Stripe customer ID, last report date
- **Onboarding checklist:** mirror `client_onboarding_skill.md` steps
- **Report log:** link to `docs/reports/weekly_siem_*.md` paths

### Example prompts

> Search Notion for "GreenLeaf" and show onboarding status.

> Create a Notion task: Weekly SIEM report due Friday for ACME — link progress file path.

### Manual setup

1. Enable Notion plugin in Cursor settings
2. Authenticate Notion workspace when prompted
3. Share relevant databases with the Notion integration

No secrets in repo — OAuth handled by plugin.

---

## Slack MCP

**Purpose:** Alert Jason on CRITICAL triage escalations from `new_finding_triage_skill.md`.

### Typical config pattern

```json
{
  "mcpServers": {
    "slack": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-slack"],
      "env": {
        "SLACK_BOT_TOKEN": "xoxb-YOUR-BOT-TOKEN",
        "SLACK_TEAM_ID": "T0XXXXXXX"
      }
    }
  }
}
```

### Jason must do manually

1. Create Slack app at https://api.slack.com/apps
2. Add bot scopes: `chat:write`, `channels:read`
3. Install to workspace, copy `xoxb-` token
4. Create `#boundry-alerts` channel

### Example prompt

> Post to #boundry-alerts: CRITICAL finding #42 — VPN drop on GreenLeaf. Triage note attached. Escalation required.

---

## Cloudflare MCP Portals (scale phase)

When Jason runs **multi-client** MCP with credential isolation:

Reference: Cloudflare MCP Portals pattern (Justin Girard event) — expose MCP tools through a Cloudflare Worker portal at a custom domain.

### When to use

- Multiple client contexts must not share raw API keys
- Agents need minimized tool surface per client
- Gateway DLP blocks credential leakage in prompts

### Query params (optimize context)

```
https://mcp.boundry.ai/?optimize_context=true&minimize_tools=true
```

- `optimize_context` — reduce token load from tool schemas
- `minimize_tools` — expose only tools needed for current skill

### Jason must do manually

1. Cloudflare account + Zero Trust
2. Deploy MCP portal Worker (separate repo when ready)
3. Gateway DLP rules: block `sk_`, `rk_`, `xoxb-`, `.terminal_token` patterns in egress
4. Per-client subdomains or API keys mapped to tool allowlists

**Current phase:** Single-operator (Jason). Use direct MCP in Cursor until second analyst or client-facing agents ship.

---

## Combined example `~/.cursor/mcp.json`

```json
{
  "mcpServers": {
    "stripe": {
      "url": "https://mcp.stripe.com"
    },
    "notion": {
      "url": "https://mcp.notion.com/mcp"
    },
    "slack": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-slack"],
      "env": {
        "SLACK_BOT_TOKEN": "xoxb-PLACEHOLDER",
        "SLACK_TEAM_ID": "T0PLACEHOLDER"
      }
    }
  }
}
```

Adjust Notion URL to match your plugin's documented endpoint. Restart Cursor after changes.

---

## Boundry.AI local MCP (separate)

`C:\Dev\boundry-mcp-server\server.py` — Claude Desktop integration with 7 security tools (`get_recent_threats`, `lookup_ip_reputation`, etc.). Requires VirusTotal + Shodan API keys. **Not the same** as Stripe/Notion/Slack business MCPs above.

---

## Security rules

1. Never paste live `STRIPE_SECRET_KEY`, Slack tokens, or `.terminal_token` into skills or progress files
2. Use Stripe OAuth or restricted keys — not full secret keys in agent context
3. Progress files are gitignored — still avoid storing full API keys there
4. Cloudflare Gateway DLP before exposing MCP to client-facing agents

---

## Blockers checklist

| Item | Blocker | Resolution |
|------|---------|------------|
| Weekly report billing step | Stripe MCP not OAuth'd | Complete OAuth at first Stripe MCP use |
| Slack escalation step | No bot token | Create Slack app, add to mcp.json |
| Notion CRM step | Plugin not authenticated | Enable Notion plugin in Cursor |
| Splunk health in reports | `SPLUNK_HEC_TOKEN` unset | Set env var or POST `/api/splunk/token` |
