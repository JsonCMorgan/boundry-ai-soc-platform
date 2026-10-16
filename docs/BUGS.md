# Boundry.AI — Bug / defect log

**Purpose:** Before “fixing” something, check here so we don’t rediscover known issues.  
**How to add:** new row at top; status `open` / `mitigated` / `closed`.  
**Last updated:** 2026-10-11

| ID | Status | Area | Summary | Notes |
|----|--------|------|---------|-------|
| B008 | closed | Repo path | Renamed repo folder to `C:\Dev\MSSP` | True rename confirmed 2026-10-11; old path gone; not a junction |
| B001 | open | VPN | Kill switch still OFF on host | Pre-client M5; NordVPN Settings → Kill Switch; verify `/api/vpn/status` |
| B009 | open | Auth | SECRET_KEY still unset in env (dev file fallback) | Pre-client M1; see PRE_CLIENT_HARDENING.md |
| B010 | open | Alerts | Gmail alert path not configured | Pre-client M4; use IR mini local alternate until set |
| B002 | open | Auth | Default `SECRET_KEY` is forgeable | Pre-client M1; set env in production |
| B003 | open | Alerts | Email alert chain needs `GMAIL_APP_PASSWORD` | Pre-client M4 |
| B004 | open | Multi-tenant | Client data isolation not implemented | Pre-client M2 |
| B005 | mitigated | VPN status | False offline when adapter Up but heartbeat lag | Fixed: adapter-primary in `vpn_monitor.py` |
| B006 | mitigated | EDR | MSI/CCM installer noise + console legend | Legend + variants shipped |
| B007 | mitigated | Sec+ MCQ | Longest-option length bias | Parallel-form pack + length lint |

When a chat finds a new defect: add a row here before large refactors.
