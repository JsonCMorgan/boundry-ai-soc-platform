"""
G5 — Simulated Microsoft Sentinel workspace blades (offline UI, no Azure).

Option A: practice Incidents / Entities / Hunting panes the way L1 sees them
in a Sentinel-style workspace. Original Boundry sample data only.
Show me blades → Prove it with blade focus + disposition.
"""

from __future__ import annotations

from typing import Any

import career_instances
import career_rationale

TRACK_TITLE = "Sentinel Workspace Lab"
TRACK_BLURB = (
    "Practice the Microsoft Sentinel workspace layout used by many Canadian MSSPs. "
    "You will read three blades: Incidents (alerts), Entities (who/what is involved), "
    "and Hunting (query results). Cases cover SMB Practice threats Boundry "
    "is likely to see (BEC, spray, MFA fatigue, ransomware, OAuth consent, leavers). "
    "Each open randomizes hosts, users, and IPs via a seed. No Azure subscription needed."
)

PASS_PCT = 70

PRIMER = [
    {
        "term": "Microsoft Sentinel",
        "plain": "A cloud SIEM from Microsoft. Analysts open a workspace, triage incidents, inspect related entities, and run hunts with KQL (Kusto Query Language).",
    },
    {
        "term": "Blade",
        "plain": "A named pane or page in the workspace UI. Here we use three: Incidents, Entities, and Hunting.",
    },
    {
        "term": "Incident / alert",
        "plain": "A grouped security finding the SIEM raised. Severity, tactics, and product name live here. L1 starts by reading the incident story.",
    },
    {
        "term": "Entity",
        "plain": "A person, host, IP, or account tied to the incident. Entities answer who and what, not just that an alert fired.",
    },
    {
        "term": "Hunting",
        "plain": "Running a focused KQL query to confirm or expand the story (more failed sign-ins, related hosts, rare ports). Hunting is evidence gathering, not guessing.",
    },
    {
        "term": "Blade focus",
        "plain": "Which blade holds the decisive evidence for your next action. You still read all three; focus means where the prove-it fact lives.",
    },
]


def _case(
    cid: str,
    title: str,
    difficulty: int,
    client: str,
    incident: dict[str, Any],
    entities: list[dict[str, str]],
    hunt: dict[str, Any],
    blade_focus: str,
    disposition: str,
    teach: str,
    checklist: dict[str, bool],
) -> dict[str, Any]:
    return {
        "id": cid,
        "title": title,
        "difficulty": difficulty,
        "client": client,
        "incident": incident,
        "entities": entities,
        "hunt": hunt,
        "correct_blade": blade_focus,
        "correct_disposition": disposition,
        "teach": teach,
        "checklist_answers": checklist,
    }


CASES: list[dict[str, Any]] = [
    _case(
        "spray_signin_fail",
        "Password spray on Contoso finance",
        1,
        "Contoso",
        {
            "name": "Multiple failed sign-ins from single IP",
            "severity": "High",
            "product": "Microsoft Entra ID Protection (practice stub)",
            "tactics": "Credential Access",
            "status": "New",
            "summary": (
                "Incident groups 48 failed SigninLogs rows for finance users in 12 minutes. "
                "Same source IP. No successful MFA yet in the incident timeline."
            ),
        },
        [
            {"type": "IP", "value": "203.0.113.44", "role": "Source of failed auth"},
            {"type": "User", "value": "a.chen@contoso.lab", "role": "Targeted account"},
            {"type": "User", "value": "m.okonkwo@contoso.lab", "role": "Targeted account"},
            {"type": "App", "value": "OfficeHome", "role": "Sign-in app"},
        ],
        {
            "query_title": "Failed sign-ins by IP (last 1h)",
            "kql": (
                "SigninLogs\n"
                "| where TimeGenerated > ago(1h)\n"
                "| where ResultType != 0\n"
                "| where IPAddress == '203.0.113.44'\n"
                "| summarize failures=count(), users=dcount(UserPrincipalName) by IPAddress\n"
                "| where failures > 20"
            ),
            "rows": [
                {"IPAddress": "203.0.113.44", "failures": "48", "users": "6"},
            ],
            "note": "Hunt confirms one IP hitting many users with high failure count.",
        },
        "hunting",
        "escalate_identity",
        "Incident names the spray. Entities name victims and IP. Hunting proves volume "
        "across users. Escalate identity with the IP and failure counts.",
        {
            "read_incident_severity": True,
            "entities_identify_actor_or_target": True,
            "hunt_supports_story": True,
            "close_without_hunt": False,
        },
    ),
    _case(
        "impossible_travel_ok",
        "Impossible travel after VPN jump",
        1,
        "NorthPeak",
        {
            "name": "Impossible travel / atypical location",
            "severity": "Medium",
            "product": "Microsoft Entra ID Protection (practice stub)",
            "tactics": "Initial Access",
            "status": "New",
            "summary": (
                "User signed in from Toronto, then Frankfurt 40 minutes later. "
                "Incident severity Medium. MFA succeeded on both."
            ),
        },
        [
            {"type": "User", "value": "s.reid@northpeak.lab", "role": "Account"},
            {"type": "IP", "value": "198.51.100.12", "role": "Toronto office egress"},
            {"type": "IP", "value": "198.51.100.90", "role": "Corporate VPN egress (EU POPs)"},
            {"type": "Device", "value": "NP-LAPTOP-18", "role": "Managed device, compliant"},
        ],
        {
            "query_title": "Sign-in locations for user (last 6h)",
            "kql": (
                "SigninLogs\n"
                "| where TimeGenerated > ago(6h)\n"
                "| where UserPrincipalName == 's.reid@northpeak.lab'\n"
                "| project TimeGenerated, IPAddress, Location, ResultType, "
                "ConditionalAccessStatus, DeviceDetail"
            ),
            "rows": [
                {
                    "TimeGenerated": "13:02",
                    "IPAddress": "198.51.100.12",
                    "Location": "Toronto, CA",
                    "ResultType": "0",
                    "ConditionalAccessStatus": "success",
                    "DeviceDetail": "NP-LAPTOP-18 compliant",
                },
                {
                    "TimeGenerated": "13:42",
                    "IPAddress": "198.51.100.90",
                    "Location": "Frankfurt, DE",
                    "ResultType": "0",
                    "ConditionalAccessStatus": "success",
                    "DeviceDetail": "NP-LAPTOP-18 compliant",
                },
            ],
            "note": (
                "Entities list the Frankfurt IP as corporate VPN egress. "
                "Same managed device, MFA OK, CA success. Classic VPN false positive."
            ),
        },
        "entities",
        "close_fp_expected",
        "The decisive fact is entity context: Frankfurt IP is known VPN egress on a "
        "compliant device. Close as expected travel/VPN, document the entity mapping.",
        {
            "read_incident_severity": True,
            "entities_identify_actor_or_target": True,
            "hunt_supports_story": True,
            "close_without_hunt": False,
        },
    ),
    _case(
        "host_beacon_alert",
        "Host beaconing to rare IP",
        2,
        "Harbor Retail",
        {
            "name": "Rare outbound connection from workstation",
            "severity": "High",
            "product": "Microsoft Defender for Endpoint (practice stub)",
            "tactics": "Command and Control",
            "status": "Active",
            "summary": (
                "WS-RETAIL-04 opened repeated HTTPS to 203.0.113.88 every 5 minutes. "
                "No user ticket explaining the traffic."
            ),
        },
        [
            {"type": "Host", "value": "WS-RETAIL-04", "role": "Source host"},
            {"type": "IP", "value": "203.0.113.88", "role": "Rare destination"},
            {"type": "User", "value": "pos.clerk@harbor.lab", "role": "Logged-on user"},
            {"type": "Process", "value": "curl.exe", "role": "Initiating process (from EDR sync)"},
        ],
        {
            "query_title": "DeviceNetworkEvents to destination",
            "kql": (
                "DeviceNetworkEvents\n"
                "| where TimeGenerated > ago(24h)\n"
                "| where RemoteIP == '203.0.113.88'\n"
                "| summarize connections=count(), hosts=dcount(DeviceName) "
                "by RemoteIP, InitiatingProcessFileName"
            ),
            "rows": [
                {
                    "RemoteIP": "203.0.113.88",
                    "InitiatingProcessFileName": "curl.exe",
                    "connections": "288",
                    "hosts": "1",
                },
            ],
            "note": "Single host, curl.exe, high connection count to a rare IP.",
        },
        "incidents",
        "escalate_endpoint",
        "Incident severity and C2 tactic already justify escalate. Entities + hunt "
        "confirm host and process. Do not close as FP without a business owner story.",
        {
            "read_incident_severity": True,
            "entities_identify_actor_or_target": True,
            "hunt_supports_story": True,
            "close_without_hunt": False,
        },
    ),
    _case(
        "hunt_only_noise",
        "Scheduled hunt finds old admin tool",
        2,
        "Contoso",
        {
            "name": "Custom detection: PsExec-like binary",
            "severity": "Low",
            "product": "Analytics rule (practice stub)",
            "tactics": "Execution",
            "status": "New",
            "summary": (
                "Weekly hunt rule fired on one host. Binary name matches admin remote "
                "tooling. No lateral movement alerts in the last 7 days for this host."
            ),
        },
        [
            {"type": "Host", "value": "JUMP-IT-02", "role": "Jump box (IT)"},
            {"type": "User", "value": "svc.jump@contoso.lab", "role": "Service account for patching"},
            {"type": "File", "value": "psexec.exe", "role": "Detected tool name"},
        ],
        {
            "query_title": "Process creates named psexec on jump boxes",
            "kql": (
                "DeviceProcessEvents\n"
                "| where TimeGenerated > ago(7d)\n"
                "| where FileName =~ 'psexec.exe'\n"
                "| where DeviceName startswith 'JUMP-'\n"
                "| summarize hits=count() by DeviceName, AccountName, FolderPath"
            ),
            "rows": [
                {
                    "DeviceName": "JUMP-IT-02",
                    "AccountName": "svc.jump",
                    "FolderPath": "C:\\Program Files\\Sysinternals\\",
                    "hits": "3",
                },
            ],
            "note": (
                "Hunt shows expected path on an IT jump box under the patching service "
                "account. Incident severity is Low for a reason."
            ),
        },
        "hunting",
        "close_fp_expected",
        "Hunting path + service account on a jump box is expected admin tooling. "
        "Close as authorized activity after documenting the hunt rows.",
        {
            "read_incident_severity": True,
            "entities_identify_actor_or_target": True,
            "hunt_supports_story": True,
            "close_without_hunt": False,
        },
    ),
    # —— Boundry / SMB MSSP threat set (hire desk + owner Practice clients) ——
    _case(
        "mailbox_forward_bec",
        "External forward on Contoso CFO mailbox",
        2,
        "Contoso",
        {
            "name": "Suspicious inbox rule / external forward",
            "severity": "High",
            "product": "Microsoft 365 Defender (practice stub)",
            "tactics": "Persistence, Collection",
            "status": "New",
            "summary": (
                "New inbox rule forwards Contoso CFO mail to finance-pay.example. "
                "Created at 02:14 local. No travel note. MFA fatigue events earlier that night."
            ),
        },
        [
            {"type": "User", "value": "cfo@contoso.lab", "role": "Mailbox owner"},
            {"type": "Domain", "value": "finance-pay.example", "role": "External forward target"},
            {"type": "IP", "value": "203.0.113.91", "role": "Session that created the rule"},
            {"type": "App", "value": "Outlook Web", "role": "Client used for rule create"},
        ],
        {
            "query_title": "Mailbox audit: New-InboxRule / Set-Mailbox",
            "kql": (
                "OfficeActivity\n"
                "| where TimeGenerated > ago(24h)\n"
                "| where Operation in ('New-InboxRule','Set-Mailbox','UpdateInboxRules')\n"
                "| where UserId == 'cfo@contoso.lab'\n"
                "| project TimeGenerated, Operation, ClientIP, Parameters"
            ),
            "rows": [
                {
                    "TimeGenerated": "02:14",
                    "Operation": "New-InboxRule",
                    "ClientIP": "203.0.113.91",
                    "Parameters": "ForwardTo=finance-pay.example",
                },
            ],
            "note": "Hunt confirms the forward rule creation. BEC persistence, not a one-off phish click.",
        },
        "entities",
        "escalate_identity",
        "External forward on a finance VIP is classic BEC persistence. Entities name the "
        "destination domain. Escalate identity, revoke sessions, remove the rule.",
        {
            "read_incident_severity": True,
            "entities_identify_actor_or_target": True,
            "hunt_supports_story": True,
            "close_without_hunt": False,
        },
    ),
    _case(
        "mfa_fatigue_push",
        "MFA fatigue then success — NorthPeak exec",
        2,
        "NorthPeak",
        {
            "name": "MFA fatigue / repeated push then success",
            "severity": "High",
            "product": "Microsoft Entra ID Protection (practice stub)",
            "tactics": "Credential Access, Initial Access",
            "status": "New",
            "summary": (
                "Fourteen MFA denials for one NorthPeak exec in 9 minutes, then one success "
                "from an unfamiliar IP. No travel ticket."
            ),
        },
        [
            {"type": "User", "value": "vp.ops@northpeak.lab", "role": "Targeted executive"},
            {"type": "IP", "value": "203.0.113.55", "role": "Unfamiliar success IP"},
            {"type": "App", "value": "Microsoft Authenticator", "role": "MFA method"},
            {"type": "Device", "value": "Unknown / non-compliant", "role": "Device at success"},
        ],
        {
            "query_title": "MFA challenge outcomes for user",
            "kql": (
                "SigninLogs\n"
                "| where TimeGenerated > ago(2h)\n"
                "| where UserPrincipalName == 'vp.ops@northpeak.lab'\n"
                "| summarize denials=countif(ResultDescription has 'MFA'), "
                "successes=countif(ResultType == 0) by IPAddress"
            ),
            "rows": [
                {"IPAddress": "203.0.113.55", "denials": "14", "successes": "1"},
            ],
            "note": "Hunt shows push-bomb volume then success from the same odd IP.",
        },
        "hunting",
        "escalate_identity",
        "Fatigue then success is takeover risk. Hunting volume is the prove-it. "
        "Escalate identity: revoke sessions, reset MFA, call the user.",
        {
            "read_incident_severity": True,
            "entities_identify_actor_or_target": True,
            "hunt_supports_story": True,
            "close_without_hunt": False,
        },
    ),
    _case(
        "oauth_consent_phish",
        "Malicious OAuth app consent — Contoso AP clerk",
        2,
        "Contoso",
        {
            "name": "Risky OAuth application consent",
            "severity": "High",
            "product": "Microsoft Entra ID (practice stub)",
            "tactics": "Persistence, Collection",
            "status": "New",
            "summary": (
                "AP clerk consented to app 'Invoice Sync Pro' requesting Mail.Read and "
                "Files.ReadWrite.All. Publisher unverified. Phish email reported earlier."
            ),
        },
        [
            {"type": "User", "value": "ap.clerk@contoso.lab", "role": "Consenting user"},
            {"type": "App", "value": "Invoice Sync Pro", "role": "Unverified OAuth app"},
            {"type": "URL", "value": "https://login.microsoftonline.com/.../consent", "role": "Consent path"},
        ],
        {
            "query_title": "AuditLogs: Consent to application",
            "kql": (
                "AuditLogs\n"
                "| where TimeGenerated > ago(24h)\n"
                "| where OperationName == 'Consent to application'\n"
                "| where TargetResources has 'Invoice Sync Pro'\n"
                "| project TimeGenerated, InitiatedBy, Result, TargetResources"
            ),
            "rows": [
                {
                    "TimeGenerated": "10:41",
                    "InitiatedBy": "ap.clerk@contoso.lab",
                    "Result": "success",
                    "TargetResources": "Invoice Sync Pro; Mail.Read; Files.ReadWrite.All",
                },
            ],
            "note": "Consent grant is the persistence. Hunt proves the scopes.",
        },
        "entities",
        "escalate_identity",
        "Illicit consent is identity persistence. Entities name the app and scopes. "
        "Escalate: revoke consent, reset sessions, warn AP.",
        {
            "read_incident_severity": True,
            "entities_identify_actor_or_target": True,
            "hunt_supports_story": True,
            "close_without_hunt": False,
        },
    ),
    _case(
        "ransom_mass_rename",
        "Harbor POS host — mass rename + note file",
        3,
        "Harbor Retail",
        {
            "name": "Ransomware-like mass file rename",
            "severity": "Critical",
            "product": "Microsoft Defender for Endpoint (practice stub)",
            "tactics": "Impact",
            "status": "Active",
            "summary": (
                "WH-PC07 created HOW_TO_DECRYPT.txt and renamed hundreds of files in minutes. "
                "No backup job in the change calendar for this host."
            ),
        },
        [
            {"type": "Host", "value": "WH-PC07", "role": "Warehouse POS / office PC"},
            {"type": "File", "value": "HOW_TO_DECRYPT.txt", "role": "Ransom note"},
            {"type": "User", "value": "pos.clerk@harbor.lab", "role": "Logged-on user"},
            {"type": "Process", "value": "encryptor.exe", "role": "Suspect process"},
        ],
        {
            "query_title": "File rename volume on host",
            "kql": (
                "DeviceFileEvents\n"
                "| where TimeGenerated > ago(2h)\n"
                "| where DeviceName == 'WH-PC07'\n"
                "| where ActionType == 'FileRenamed'\n"
                "| summarize renames=count() by DeviceName, InitiatingProcessFileName"
            ),
            "rows": [
                {
                    "DeviceName": "WH-PC07",
                    "InitiatingProcessFileName": "encryptor.exe",
                    "renames": "412",
                },
            ],
            "note": "Incident already Critical. Hunt confirms mass rename volume.",
        },
        "incidents",
        "escalate_endpoint",
        "Critical Impact + ransom note is contain-now. Incident blade is enough to escalate "
        "endpoint; hunt only reinforces. Isolate and hand to IR.",
        {
            "read_incident_severity": True,
            "entities_identify_actor_or_target": True,
            "hunt_supports_story": True,
            "close_without_hunt": False,
        },
    ),
    _case(
        "after_hours_pos_fp",
        "Harbor POS after-hours login — inventory window",
        1,
        "Harbor Retail",
        {
            "name": "After-hours interactive logon on POS",
            "severity": "Medium",
            "product": "Microsoft Defender for Identity (practice stub)",
            "tactics": "Initial Access",
            "status": "New",
            "summary": (
                "Interactive logon on WS-RETAIL-02 at 23:40 local. Store closed at 21:00. "
                "Change ticket INV-118 covers overnight inventory recount."
            ),
        },
        [
            {"type": "Host", "value": "WS-RETAIL-02", "role": "Retail POS"},
            {"type": "User", "value": "inv.lead@harbor.lab", "role": "Inventory lead (ticket owner)"},
            {"type": "IP", "value": "10.20.30.14", "role": "Store LAN"},
        ],
        {
            "query_title": "Logons on POS during window",
            "kql": (
                "SecurityEvent\n"
                "| where TimeGenerated > ago(12h)\n"
                "| where EventID == 4624\n"
                "| where Computer == 'WS-RETAIL-02'\n"
                "| project TimeGenerated, Account, LogonType, IpAddress"
            ),
            "rows": [
                {
                    "TimeGenerated": "23:40",
                    "Account": "inv.lead",
                    "LogonType": "2",
                    "IpAddress": "10.20.30.14",
                },
            ],
            "note": "Entity + ticket context explains after-hours. Local store IP, expected account.",
        },
        "entities",
        "close_fp_expected",
        "Retail stores often run overnight inventory. Entities + change ticket beat "
        "the Medium after-hours alert. Close as expected, document INV-118.",
        {
            "read_incident_severity": True,
            "entities_identify_actor_or_target": True,
            "hunt_supports_story": True,
            "close_without_hunt": False,
        },
    ),
    _case(
        "guest_admin_add",
        "Guest user added to Contoso Global Admins",
        3,
        "Contoso",
        {
            "name": "Privileged role assignment to guest",
            "severity": "Critical",
            "product": "Microsoft Entra ID (practice stub)",
            "tactics": "Privilege Escalation, Persistence",
            "status": "New",
            "summary": (
                "Guest identity vendor.temp@fabrikam.lab added to Global Administrator. "
                "No change ticket. Initiated from a newly enrolled device."
            ),
        },
        [
            {"type": "User", "value": "vendor.temp@fabrikam.lab", "role": "Guest principal"},
            {"type": "User", "value": "helpdesk.svc@contoso.lab", "role": "Initiator (possibly compromised)"},
            {"type": "Group", "value": "Global Administrator", "role": "Role assigned"},
        ],
        {
            "query_title": "Directory role assignments",
            "kql": (
                "AuditLogs\n"
                "| where TimeGenerated > ago(24h)\n"
                "| where OperationName has 'Add member to role'\n"
                "| where TargetResources has 'Global Administrator'\n"
                "| project TimeGenerated, InitiatedBy, TargetResources, Result"
            ),
            "rows": [
                {
                    "TimeGenerated": "04:02",
                    "InitiatedBy": "helpdesk.svc@contoso.lab",
                    "TargetResources": "vendor.temp@fabrikam.lab → Global Administrator",
                    "Result": "success",
                },
            ],
            "note": "Guest + Global Admin with no ticket is never expected.",
        },
        "incidents",
        "escalate_identity",
        "Critical privilege on a guest is immediate identity IR. Incident severity "
        "and role name are enough to escalate. Hunt confirms initiator.",
        {
            "read_incident_severity": True,
            "entities_identify_actor_or_target": True,
            "hunt_supports_story": True,
            "close_without_hunt": False,
        },
    ),
    _case(
        "token_replay_unfamiliar",
        "Token replay / unfamiliar properties — NorthPeak",
        2,
        "NorthPeak",
        {
            "name": "Unfamiliar sign-in properties / token anomaly",
            "severity": "High",
            "product": "Microsoft Entra ID Protection (practice stub)",
            "tactics": "Initial Access",
            "status": "New",
            "summary": (
                "Successful sign-in with valid token but unfamiliar properties: new ASN, "
                "no device ID, ClientApp=Browser from a country the user never visits."
            ),
        },
        [
            {"type": "User", "value": "finance.lead@northpeak.lab", "role": "Account"},
            {"type": "IP", "value": "198.51.100.200", "role": "Unfamiliar ASN egress"},
            {"type": "Device", "value": "(none / missing deviceId)", "role": "No managed device"},
        ],
        {
            "query_title": "Sign-ins missing device compliance",
            "kql": (
                "SigninLogs\n"
                "| where TimeGenerated > ago(6h)\n"
                "| where UserPrincipalName == 'finance.lead@northpeak.lab'\n"
                "| where ResultType == 0\n"
                "| project TimeGenerated, IPAddress, Location, DeviceDetail, "
                "ClientAppUsed, RiskDetail"
            ),
            "rows": [
                {
                    "TimeGenerated": "07:18",
                    "IPAddress": "198.51.100.200",
                    "Location": "Unknown / rare country",
                    "DeviceDetail": "missing deviceId",
                    "ClientAppUsed": "Browser",
                    "RiskDetail": "unfamiliarProperties",
                },
            ],
            "note": "Success without device binding after token theft patterns.",
        },
        "hunting",
        "escalate_identity",
        "Unfamiliar properties + success without a managed device is session theft risk. "
        "Hunt rows prove the anomaly. Escalate identity and revoke refresh tokens.",
        {
            "read_incident_severity": True,
            "entities_identify_actor_or_target": True,
            "hunt_supports_story": True,
            "close_without_hunt": False,
        },
    ),
    _case(
        "mass_spo_download",
        "SharePoint mass download — Contoso leaver week",
        2,
        "Contoso",
        {
            "name": "Mass download from SharePoint site",
            "severity": "Medium",
            "product": "Microsoft 365 Defender (practice stub)",
            "tactics": "Exfiltration",
            "status": "New",
            "summary": (
                "User downloaded 1,200 files from Finance site in 20 minutes. "
                "HR shows last day tomorrow. No DLP block fired."
            ),
        },
        [
            {"type": "User", "value": "r.nguyen@contoso.lab", "role": "Leaver (last day tomorrow)"},
            {"type": "URL", "value": "https://contoso.sharepoint.com/sites/Finance", "role": "Site"},
            {"type": "IP", "value": "198.51.100.12", "role": "Office egress"},
        ],
        {
            "query_title": "SharePoint file download volume",
            "kql": (
                "OfficeActivity\n"
                "| where TimeGenerated > ago(6h)\n"
                "| where Operation == 'FileDownloaded'\n"
                "| where UserId == 'r.nguyen@contoso.lab'\n"
                "| summarize downloads=count() by Site_Url"
            ),
            "rows": [
                {
                    "Site_Url": "https://contoso.sharepoint.com/sites/Finance",
                    "downloads": "1200",
                },
            ],
            "note": "Hunt confirms volume. Leaver context makes escalate (not watch-only) correct.",
        },
        "hunting",
        "escalate_identity",
        "Mass download on a leaver is insider / data-risk. Hunting volume is decisive. "
        "Escalate identity / IR for access review and HR coordination. Do not watch-only.",
        {
            "read_incident_severity": True,
            "entities_identify_actor_or_target": True,
            "hunt_supports_story": True,
            "close_without_hunt": False,
        },
    ),
    _case(
        "signed_ps_sccm_fp",
        "Signed PowerShell from SCCM — Contoso patch window",
        1,
        "Contoso",
        {
            "name": "Suspicious PowerShell / encoded command",
            "severity": "Medium",
            "product": "Microsoft Defender for Endpoint (practice stub)",
            "tactics": "Execution",
            "status": "New",
            "summary": (
                "Encoded PowerShell on WS-IT-21 during CHG-902 patch window. "
                "Parent process is ccmexec (ConfigMgr client)."
            ),
        },
        [
            {"type": "Host", "value": "WS-IT-21", "role": "Managed workstation"},
            {"type": "Process", "value": "powershell.exe", "role": "Child process"},
            {"type": "Process", "value": "ccmexec.exe", "role": "SCCM client parent"},
            {"type": "User", "value": "SYSTEM", "role": "Process account"},
        ],
        {
            "query_title": "Process tree around PowerShell",
            "kql": (
                "DeviceProcessEvents\n"
                "| where TimeGenerated > ago(4h)\n"
                "| where DeviceName == 'WS-IT-21'\n"
                "| where FileName in ('powershell.exe','ccmexec.exe')\n"
                "| project TimeGenerated, FileName, InitiatingProcessFileName, AccountName"
            ),
            "rows": [
                {
                    "TimeGenerated": "22:10",
                    "FileName": "powershell.exe",
                    "InitiatingProcessFileName": "ccmexec.exe",
                    "AccountName": "SYSTEM",
                },
            ],
            "note": "Parent ccmexec + change window = expected patch automation.",
        },
        "hunting",
        "close_fp_expected",
        "Encoded PowerShell looks scary until hunting shows SCCM parent in a patch window. "
        "Close as expected admin automation; document CHG-902.",
        {
            "read_incident_severity": True,
            "entities_identify_actor_or_target": True,
            "hunt_supports_story": True,
            "close_without_hunt": False,
        },
    ),
]


def random_case_url() -> dict[str, str]:
    """Fresh random case + seed for hub 'Surprise me' button."""
    return career_instances.next_scenario(case_ids(), None, "/career/sentinel")

BLADES = [
    {
        "id": "incidents",
        "label": "Incidents blade (alert story / severity / tactics)",
        "why": "Start here when the incident title, severity, or product name already tells you escalate vs watch.",
    },
    {
        "id": "entities",
        "label": "Entities blade (user / host / IP / device context)",
        "why": "Start here when the prove-it fact is who owns the IP, whether the device is managed, or role of the account.",
    },
    {
        "id": "hunting",
        "label": "Hunting blade (KQL result that confirms volume or path)",
        "why": "Start here when you need counts, paths, or multi-user volume that the incident card alone does not prove.",
    },
]

DISPOSITIONS = [
    {
        "id": "escalate_identity",
        "label": "Escalate to identity / IR (credential risk)",
        "why": "Spray, takeover, or MFA abuse patterns with supporting hunt volume.",
    },
    {
        "id": "escalate_endpoint",
        "label": "Escalate to endpoint / IR (host contain)",
        "why": "C2, malware process, or rare beaconing tied to a host entity.",
    },
    {
        "id": "close_fp_expected",
        "label": "Close as false positive / expected activity",
        "why": "Entities or hunt prove authorized VPN, admin tooling, or known business path.",
    },
    {
        "id": "watch_only",
        "label": "Leave open and watch only (no escalate, no close)",
        "why": "Rarely right when severity is High or hunt already confirms volume.",
    },
]

CHECKLIST_ITEMS = [
    {
        "id": "read_incident_severity",
        "label": "I read the Incidents blade (name, severity, tactics, summary)",
    },
    {
        "id": "entities_identify_actor_or_target",
        "label": "Entities name at least one actor, target, host, or IP that matters",
    },
    {
        "id": "hunt_supports_story",
        "label": "Hunting rows support (or overturn) the incident story with evidence",
    },
    {
        "id": "close_without_hunt",
        "label": "I would close this without opening Entities or Hunting",
    },
]


def case_ids() -> list[str]:
    """Ordered case ids for next-scenario rotation."""
    return [c["id"] for c in CASES]


def list_cases() -> list[dict[str, Any]]:
    """Hub cards without full blade payloads."""
    return [
        {
            "id": c["id"],
            "title": c["title"],
            "difficulty": c["difficulty"],
            "client": c["client"],
            "teach": c["teach"],
            "severity": c["incident"]["severity"],
        }
        for c in CASES
    ]


def get_case(case_id: str) -> dict[str, Any] | None:
    """Return one Sentinel workspace case (canonical, no variants)."""
    for c in CASES:
        if c["id"] == case_id:
            return c
    return None


def materialize_case(case_id: str, seed: str | None = None) -> dict[str, Any] | None:
    """Variant instance: new users/IPs/hosts across incident, entities, hunt."""
    case = get_case(case_id)
    if not case:
        return None
    return career_instances.materialize_generic(
        case,
        seed,
        host_key=None,
        user_key=None,
        text_keys=["teach", "incident", "entities", "hunt"],
        allow_ip=True,
    )


def next_after(case_id: str) -> dict[str, str]:
    """Random different case + fresh seed under /career/sentinel."""
    return career_instances.next_scenario(case_ids(), case_id, "/career/sentinel")


def grade_sentinel(
    case_id: str,
    checklist: dict[str, bool],
    blade_id: str,
    disposition: str,
) -> dict[str, Any]:
    """Grade checklist + blade focus + disposition."""
    case = get_case(case_id)
    if not case:
        return {"ok": False, "error": "Unknown case"}
    answers = case["checklist_answers"]
    items = []
    hit = 0
    for item in CHECKLIST_ITEMS:
        iid = item["id"]
        expected = bool(answers.get(iid))
        got = bool(checklist.get(iid))
        ok = got == expected
        if ok:
            hit += 1
        items.append({
            "id": iid,
            "label": item["label"],
            "expected": expected,
            "got": got,
            "correct": ok,
        })
    blade_ok = (blade_id or "").strip() == case["correct_blade"]
    disp_ok = (disposition or "").strip() == case["correct_disposition"]
    # Checklist 4 + blade 2 + disposition 2
    score = hit + (2 if blade_ok else 0) + (2 if disp_ok else 0)
    total = len(CHECKLIST_ITEMS) + 4
    pct = round(100 * score / total)

    blade_meta = next(
        (b for b in BLADES if b["id"] == case["correct_blade"]),
        None,
    )
    disp_meta = next(
        (d for d in DISPOSITIONS if d["id"] == case["correct_disposition"]),
        None,
    )

    return {
        "ok": True,
        "pct": pct,
        "passed": pct >= PASS_PCT,
        "checklist": items,
        "blade_correct": blade_ok,
        "correct_blade": case["correct_blade"],
        "correct_blade_label": (blade_meta or {}).get("label") or case["correct_blade"],
        "blade_rationale": (
            f"Why this blade: {(blade_meta or {}).get('why') or ''} "
            f"For this case: {case['teach']}"
        ).strip(),
        "disposition_correct": disp_ok,
        "correct_disposition": case["correct_disposition"],
        "correct_disposition_label": (disp_meta or {}).get("label") or case["correct_disposition"],
        "disposition_rationale": (
            f"Why this disposition: {(disp_meta or {}).get('why') or ''} "
            f"For this case: {case['teach']}"
        ).strip(),
        "teach": case["teach"],
        "score": score,
        "total": total,
        "answer_chips": [
            career_rationale.chip(
                id="blade",
                label=(blade_meta or {}).get("label") or case["correct_blade"],
                matched=blade_ok,
                rationale=(
                    f"Why this blade: {(blade_meta or {}).get('why') or ''} "
                    f"For this case: {case['teach']}"
                ).strip(),
                title="Why this blade",
                row_label="Correct blade focus",
            ),
            career_rationale.disposition_chip(
                correct_id=case["correct_disposition"],
                label=(disp_meta or {}).get("label") or case["correct_disposition"],
                matched=disp_ok,
                teach=case["teach"],
                why=(disp_meta or {}).get("why") or "",
            ),
        ],
    }
