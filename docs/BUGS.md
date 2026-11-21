# Boundry.AI — Bug / defect log

**Purpose:** Before “fixing” something, check here so we don’t rediscover known issues.  
**How to add:** new row at top; status `open` / `mitigated` / `closed`.  
**Last updated:** 2026-11-20

| ID | Status | Area | Summary | Notes |
|----|--------|------|---------|-------|
| B014 | closed | Tests | Suite order-dependent: Messer tests leaked `ENABLE_MESSER_LAYER`; login/register rate limits leaked across tests | Autouse env-restore fixture + `limiter.reset()` in `tests/conftest.py` |
| B013 | closed | Sec+ MCQ | 27 Help-me/Prove-it choices truncated mid-sentence by length balancing | `tools/_fix_incomplete_mcq_backlog.py`; length lint still 0 severe |
| B012 | closed | SOC Floor | Adding a task to a ticket returned 500 (`db_fetchall` undefined in `soc_lab.add_case_task`) | Found by ruff F821 in CI; `tests/test_regressions.py` |
| B011 | closed | SIEM / Auth | Login throttle and preset-change SIEM events never written (`time` not imported; NameError swallowed) | Found by ruff F821 in CI; `tests/test_regressions.py` |
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
