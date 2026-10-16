# Boundry.AI — Mini incident response path (M8)

**Audience:** Jason (personal network + future SMB)  
**Last updated:** 2026-10-11  

## What counts as an incident

| Severity | Examples | Who acts |
|----------|----------|----------|
| CRITICAL | Confirmed ransomware indicators, active admin compromise, VPN drop with kill switch OFF during monitoring window | Jason immediately |
| HIGH | Valid spray with success, BEC forward rule, exposed RDP to DC-class host | Jason same day |
| MEDIUM | Suspected FP needing validation, medium vuln on exposed edge | Jason within SLA |
| LOW / INFO | Hygiene, informational scanner noise | Backlog |

## Personal-network vs SMB (this phase)

**Personal network / self-lab**

1. Detect on `/soc` or SIEM  
2. Contain what you control (isolate host, revoke session, block URL locally)  
3. Note actions in case / handoff  
4. No external client notify required  

**Future SMB client (after M1–M7)**

1. Detect → open `/soc` case with client tag  
2. Contain per playbook / SOAR gate (human approve)  
3. Notify named client contact within agreed window (draft via Comms Gym pattern)  
4. Escalate to partner/IR if out of L1 scope  
5. End-of-shift handoff with G14 rubric quality  

## Notification SLA (draft until Roy)

| Scope | First notify target |
|-------|---------------------|
| Personal | Self (immediate) |
| SMB HIGH/CRITICAL | Client contact within 4 business hours (draft; lock with Roy) |
| SMB MEDIUM | Next business day status |

## Alert path (M4)

**Preferred:** SIEM/finding → `/soc` case → email via `alert_monitor.py` when `GMAIL_APP_PASSWORD` is set.

**Local alternate (acceptable until email works):**

1. Watch `/soc` Practice + Real queue during shifts  
2. VPN monitor CRITICAL in SIEM when tunnel drops  
3. Desktop notification / Task Scheduler BoundryAI-AlertMonitor once Gmail app password is configured  
4. Document in shift handoff if email path was down  

## Do not

- Claim 24×7 MDR coverage  
- Promise Defender/Sentinel tenant response without connectors  
- Send incident details to cloud AI  
