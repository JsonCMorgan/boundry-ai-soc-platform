"""
system_scanner.py — Boundry.AI Real Machine & Network Scanner
Runs on Jason's Windows 11 machine (local only — never deployed to Railway).
Each finding maps to a CISSP domain so fixing real vulnerabilities earns XP
and teaches the exam concept at the same time.
"""

import subprocess
import socket
import threading
import ipaddress
import re
from datetime import datetime


# ─── CISSP Domain mappings for each finding category ───────────────────────
DOMAIN_MAP = {
    "firewall":        4,   # D4: Communication and Network Security
    "open_ports":      4,   # D4: Communication and Network Security
    "user_accounts":   5,   # D5: Identity and Access Management
    "defender":        7,   # D7: Security Operations
    "uac":             5,   # D5: Identity and Access Management
    "updates":         7,   # D7: Security Operations
    "shared_folders":  2,   # D2: Asset Security
    "password_policy": 5,   # D5: Identity and Access Management
    "network_device":  4,   # D4: Communication and Network Security
    "rdp_exposed":     4,   # D4: Communication and Network Security
    "smb_exposed":     2,   # D2: Asset Security
    "telnet_exposed":  4,   # D4: Communication and Network Security
}

# Severity levels: CRITICAL > HIGH > MEDIUM > LOW > INFO
SEVERITY_MAP = {
    "firewall_off":        "CRITICAL",
    "defender_off":        "CRITICAL",
    "uac_off":             "HIGH",
    "no_updates":          "HIGH",
    "guest_enabled":       "HIGH",
    "rdp_open":            "HIGH",
    "telnet_open":         "HIGH",
    "smb_open":            "MEDIUM",
    "open_share":          "MEDIUM",
    "weak_password_policy":"MEDIUM",
    "admin_account_active":"MEDIUM",
    "open_port":           "LOW",
    "device_found":        "INFO",
}

# Risky ports with their service names and CISSP relevance
RISKY_PORTS = {
    21:   ("FTP",     "CRITICAL", "Unencrypted file transfer. Use SFTP/FTPS instead."),
    22:   ("SSH",     "INFO",     "SSH open — ensure key-based auth is enforced, no root login."),
    23:   ("Telnet",  "CRITICAL", "Telnet is completely unencrypted. Disable immediately."),
    25:   ("SMTP",    "MEDIUM",   "SMTP open — verify this host should be an email relay."),
    80:   ("HTTP",    "MEDIUM",   "HTTP open — ensure this is intentional. Use HTTPS instead."),
    135:  ("RPC",     "MEDIUM",   "Windows RPC exposed. Common attack vector."),
    139:  ("NetBIOS", "MEDIUM",   "NetBIOS open — old Windows name resolution protocol."),
    443:  ("HTTPS",   "INFO",     "HTTPS open — verify certificate is valid."),
    445:  ("SMB",     "HIGH",     "SMB open — EternalBlue / WannaCry attack surface. Block externally."),
    1433: ("MSSQL",   "HIGH",     "SQL Server exposed — ensure authentication is strong."),
    3306: ("MySQL",   "HIGH",     "MySQL exposed — should not be accessible remotely."),
    3389: ("RDP",     "HIGH",     "RDP open — high-value target. Limit to VPN/allowlist only."),
    5985: ("WinRM",   "MEDIUM",   "WinRM open — remote management. Restrict to admin IPs."),
    8080: ("HTTP-Alt","LOW",      "Alternate HTTP port open. Verify what service is running."),
    8443: ("HTTPS-Alt","LOW",     "Alternate HTTPS port. Verify what service is running."),
}


def _run_ps(command, timeout=30):
    """
    Run a PowerShell command and return stdout as a string.
    Returns empty string if the command fails or times out.
    """
    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        return (result.stdout or "").strip()
    except Exception:
        return ""


def _make_finding(finding_id, title, severity, category, description, recommendation, raw_output=""):
    """Build a standardised finding dict."""
    return {
        "finding_id":      finding_id,
        "title":           title,
        "severity":        severity,
        "cissp_domain":    DOMAIN_MAP.get(category, 7),
        "category":        category,
        "description":     description,
        "recommendation":  recommendation,
        "raw_output":      raw_output[:2000],  # cap to 2KB
    }


# ─── Machine Audit Checks ──────────────────────────────────────────────────

def _check_firewall():
    """Check Windows Firewall state for all three profiles."""
    findings = []
    output = _run_ps(
        "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json"
    )
    profiles_off = []
    try:
        import json
        profiles = json.loads(output)
        if isinstance(profiles, dict):
            profiles = [profiles]
        for p in profiles:
            if str(p.get("Enabled", "True")).lower() == "false":
                profiles_off.append(p["Name"])
    except Exception:
        # If JSON parse fails, do a text search
        if "false" in output.lower():
            profiles_off.append("Unknown")

    if profiles_off:
        for name in profiles_off:
            findings.append(_make_finding(
                finding_id=f"firewall_off_{name.lower()}",
                title=f"Windows Firewall OFF — {name} profile",
                severity="CRITICAL",
                category="firewall",
                description=(
                    f"The Windows Firewall is disabled for the {name} network profile. "
                    "This removes a critical layer of host-based defence, exposing all "
                    "listening services directly to network traffic. "
                    "CISSP Domain 4 — Communication & Network Security: firewalls are a "
                    "primary preventive control. Disabling the host firewall violates "
                    'the "defence in depth" principle.'
                ),
                recommendation=(
                    f'Enable firewall: Set-NetFirewallProfile -Profile {name} -Enabled True\n'
                    "Or in Windows Security: Firewall & network protection → turn on."
                ),
                raw_output=output,
            ))
    return findings


def _check_windows_defender():
    """Check Windows Defender / Antivirus status."""
    findings = []
    output = _run_ps(
        "Get-MpComputerStatus | Select-Object AMRunningMode, RealTimeProtectionEnabled, "
        "AntispywareEnabled, AntivirusEnabled, AntivirusSignatureLastUpdated | ConvertTo-Json"
    )
    try:
        import json
        status = json.loads(output)
        if str(status.get("RealTimeProtectionEnabled", "True")).lower() == "false":
            findings.append(_make_finding(
                finding_id="defender_realtime_off",
                title="Windows Defender Real-Time Protection DISABLED",
                severity="CRITICAL",
                category="defender",
                description=(
                    "Windows Defender real-time protection is turned off. "
                    "This means malware, ransomware, and exploits can execute without "
                    "being detected or blocked. "
                    "CISSP Domain 7 — Security Operations: continuous monitoring and "
                    "endpoint protection are mandatory security operations controls."
                ),
                recommendation=(
                    "Re-enable: Set-MpPreference -DisableRealtimeMonitoring $false\n"
                    "Or: Windows Security → Virus & threat protection → turn on."
                ),
                raw_output=output,
            ))
        # Check signature age
        try:
            sig_date_str = status.get("AntivirusSignatureLastUpdated", "")
            if sig_date_str:
                # PowerShell returns a .NET date format
                sig_date = datetime.fromisoformat(str(sig_date_str)[:10])
                days_old = (datetime.utcnow() - sig_date).days
                if days_old > 7:
                    findings.append(_make_finding(
                        finding_id="defender_sigs_stale",
                        title=f"Defender signatures are {days_old} days old",
                        severity="HIGH",
                        category="defender",
                        description=(
                            f"Antivirus signatures were last updated {days_old} days ago. "
                            "New malware variants released in the past week will not be detected. "
                            "CISSP Domain 7: patch and signature currency are core operational controls."
                        ),
                        recommendation=(
                            "Update: Update-MpSignature\n"
                            "Enable automatic updates to keep signatures current."
                        ),
                        raw_output=output,
                    ))
        except Exception:
            pass
    except Exception:
        pass
    return findings


def _check_uac():
    """Check User Account Control (UAC) status."""
    findings = []
    output = _run_ps(
        r"(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' "
        r"-Name EnableLUA).EnableLUA"
    )
    if output.strip() == "0":
        findings.append(_make_finding(
            finding_id="uac_disabled",
            title="UAC (User Account Control) is DISABLED",
            severity="HIGH",
            category="uac",
            description=(
                "User Account Control is turned off on this machine. UAC is a critical "
                "Windows security boundary — it prevents applications from silently "
                "requesting admin privileges. Without it, any running process (including "
                "malware) can operate with full administrator rights. "
                "CISSP Domain 5 — Identity & Access Management: least-privilege is a "
                "foundational IAM principle. UAC enforces it at the OS level."
            ),
            recommendation=(
                r"Enable: Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' "
                r"-Name EnableLUA -Value 1\n"
                "Or: Control Panel → User Accounts → Change UAC settings → set to highest."
            ),
            raw_output=output,
        ))
    return findings


def _check_windows_update():
    """Check for pending Windows updates (critical/important)."""
    findings = []
    output = _run_ps(
        "(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()."
        "Search('IsInstalled=0 and Type=\\'Software\\'').Updates.Count"
    )
    try:
        count = int(output.strip())
        if count > 0:
            severity = "HIGH" if count >= 5 else "MEDIUM"
            findings.append(_make_finding(
                finding_id="pending_windows_updates",
                title=f"{count} Windows updates pending installation",
                severity=severity,
                category="updates",
                description=(
                    f"There are {count} uninstalled Windows updates. Unpatched systems are "
                    "the leading cause of successful exploitation. Many major breaches "
                    "(WannaCry, NotPetya) exploited known, patchable vulnerabilities. "
                    "CISSP Domain 7 — Security Operations: patch management is a core "
                    "preventive security operations control."
                ),
                recommendation=(
                    "Install updates: Settings → Windows Update → Check for updates → Install all.\n"
                    "Enable automatic updates for critical/security updates."
                ),
                raw_output=output,
            ))
    except Exception:
        pass
    return findings


def _check_user_accounts():
    """Check for risky local user account configurations."""
    findings = []
    output = _run_ps(
        "Get-LocalUser | Select-Object Name, Enabled, PasswordRequired, "
        "PasswordNeverExpires, LastLogon | ConvertTo-Json"
    )
    try:
        import json
        users = json.loads(output)
        if isinstance(users, dict):
            users = [users]
        for u in users:
            name    = str(u.get("Name", ""))
            enabled = str(u.get("Enabled", "False")).lower() == "true"

            # Guest account enabled
            if name.lower() == "guest" and enabled:
                findings.append(_make_finding(
                    finding_id="guest_account_enabled",
                    title="Guest account is ENABLED",
                    severity="HIGH",
                    category="user_accounts",
                    description=(
                        "The built-in Guest account is active. Guest accounts provide "
                        "unauthenticated access to the machine with no password required. "
                        "CISSP Domain 5 — IAM: all accounts must be authenticated and "
                        "authorised. Anonymous/guest access violates least privilege."
                    ),
                    recommendation="Disable-LocalUser -Name Guest",
                    raw_output=output,
                ))

            # Administrator account active with default name
            if name.lower() == "administrator" and enabled:
                findings.append(_make_finding(
                    finding_id="default_admin_active",
                    title="Built-in Administrator account is ACTIVE",
                    severity="MEDIUM",
                    category="user_accounts",
                    description=(
                        "The default 'Administrator' account is enabled. Attackers "
                        "specifically target this account in brute-force and credential "
                        "stuffing attacks because the name is universal and predictable. "
                        "CISSP Domain 5 — IAM: rename or disable built-in privileged accounts."
                    ),
                    recommendation=(
                        "Rename: Rename-LocalUser -Name Administrator -NewName <custom_name>\n"
                        "Or disable if not needed: Disable-LocalUser -Name Administrator"
                    ),
                    raw_output=output,
                ))

            # Password never expires
            if enabled and str(u.get("PasswordNeverExpires", "False")).lower() == "true":
                if name.lower() not in ("administrator", "guest"):
                    findings.append(_make_finding(
                        finding_id=f"pwd_never_expires_{name.lower()[:20]}",
                        title=f"Account '{name}' has password set to NEVER EXPIRE",
                        severity="MEDIUM",
                        category="password_policy",
                        description=(
                            f"The account '{name}' has 'Password Never Expires' enabled. "
                            "Permanent passwords increase the risk window if the credential "
                            "is ever compromised. "
                            "CISSP Domain 5 — IAM: password rotation is a standard access "
                            "management control."
                        ),
                        recommendation=(
                            f"Set-LocalUser -Name '{name}' -PasswordNeverExpires $false\n"
                            "Then configure a maximum password age in your local password policy."
                        ),
                        raw_output=output,
                    ))
    except Exception:
        pass
    return findings


def _check_open_ports():
    """Check for listening ports on the local machine."""
    findings = []
    output = _run_ps(
        "Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort | "
        "Sort-Object LocalPort -Unique | ConvertTo-Json"
    )
    try:
        import json
        connections = json.loads(output)
        if isinstance(connections, dict):
            connections = [connections]
        seen_ports = set()
        for conn in connections:
            port = int(conn.get("LocalPort", 0))
            addr = str(conn.get("LocalAddress", ""))
            if port in seen_ports:
                continue
            seen_ports.add(port)
            if port in RISKY_PORTS:
                service, severity, detail = RISKY_PORTS[port]
                if severity in ("CRITICAL", "HIGH", "MEDIUM"):
                    findings.append(_make_finding(
                        finding_id=f"open_port_{port}",
                        title=f"Port {port} ({service}) is listening",
                        severity=severity,
                        category="open_ports",
                        description=(
                            f"{service} is listening on port {port} (address: {addr}). "
                            f"{detail} "
                            "CISSP Domain 4 — Communication & Network Security: "
                            "every listening port is an attack surface. Only necessary "
                            "services should be running, and each should be protected."
                        ),
                        recommendation=(
                            f"Verify that {service} on port {port} is intentional and required. "
                            "If not: stop the service and block the port at the firewall.\n"
                            f"Firewall rule: New-NetFirewallRule -DisplayName 'Block {service}' "
                            f"-Direction Inbound -LocalPort {port} -Protocol TCP -Action Block"
                        ),
                        raw_output=output,
                    ))
    except Exception:
        pass
    return findings


def _check_shared_folders():
    """Check for non-default Windows file shares."""
    findings = []
    output = _run_ps(
        "Get-SmbShare | Where-Object {$_.Name -notmatch '^(ADMIN|IPC|print|C|D|E|F)\\$'} | "
        "Select-Object Name, Path, Description | ConvertTo-Json"
    )
    try:
        import json
        if not output or output == "null":
            return findings
        shares = json.loads(output)
        if isinstance(shares, dict):
            shares = [shares]
        for share in shares:
            name = str(share.get("Name", ""))
            path = str(share.get("Path", ""))
            findings.append(_make_finding(
                finding_id=f"smb_share_{name.lower()[:20]}",
                title=f"Non-default SMB share active: \\\\localhost\\{name}",
                severity="MEDIUM",
                category="shared_folders",
                description=(
                    f"File share '{name}' at path '{path}' is accessible on the network. "
                    "Each share is a potential data exfiltration point. "
                    "CISSP Domain 2 — Asset Security: data classification and access "
                    "control must be applied to all accessible assets including shares."
                ),
                recommendation=(
                    f"Review who can access \\\\localhost\\{name}. "
                    "Remove if not needed: Remove-SmbShare -Name '{name}' -Force\n"
                    "If needed: restrict permissions to specific users/groups only."
                ),
                raw_output=output,
            ))
    except Exception:
        pass
    return findings


def run_machine_audit():
    """
    Run all Windows security audit checks on the local machine.
    Returns a list of finding dicts sorted by severity.
    """
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings = []
    findings.extend(_check_firewall())
    findings.extend(_check_windows_defender())
    findings.extend(_check_uac())
    findings.extend(_check_windows_update())
    findings.extend(_check_user_accounts())
    findings.extend(_check_open_ports())
    findings.extend(_check_shared_folders())
    findings.sort(key=lambda f: severity_order.get(f["severity"], 5))
    return findings


# ─── Network Scanner ───────────────────────────────────────────────────────

def _get_local_subnet():
    """Detect the local machine's IP and derive the /24 subnet."""
    try:
        # Connect to a public IP (no actual traffic) to find the primary interface
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        # Build /24 from the local IP
        network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
        return str(network), local_ip
    except Exception:
        return "192.168.1.0/24", "192.168.1.1"


def _ping_host(ip, alive_list, lock, timeout=0.5):
    """Quick TCP connect to port 80 or 443 to see if a host is alive."""
    for port in (80, 443, 22, 445, 3389):
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                with lock:
                    alive_list.append(ip)
                return
        except Exception:
            continue


def _scan_ports(ip, ports=None, timeout=1.0):
    """Scan a list of ports on a single host. Returns list of open port numbers."""
    if ports is None:
        ports = list(RISKY_PORTS.keys()) + [8080, 8443, 8888, 5000]
    open_ports = []
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                open_ports.append(port)
        except Exception:
            continue
    return open_ports


def get_remediation_plan(finding_id):
    """
    Return a structured remediation plan for a given finding_id string.

    Returned dict keys:
      can_auto        bool    — True if PowerShell auto-remediation is available
      auto_label      str     — Button label (e.g. "Block Port 445 at Firewall")
      action_summary  str     — One sentence: what the auto-fix command does
      warning         str|None— Orange caveat the analyst must read (restart needed, etc.)
      manual_steps    list    — Numbered steps for manual remediation
      auto_command    str|None— PowerShell command to execute
      verify_command  str|None— PowerShell command to confirm fix
      verify_pass_value str|None — Expected substring in verify output (None = any output = pass)
    """
    fid = finding_id.lower()

    # ── Firewall profile off ─────────────────────────────────────────────────
    if fid.startswith("firewall_off_"):
        profile = finding_id[len("firewall_off_"):].capitalize()
        return {
            "can_auto":        True,
            "auto_label":      f"Enable {profile} Firewall",
            "action_summary":  f"Runs: Set-NetFirewallProfile -Profile {profile} -Enabled True",
            "warning":         None,
            "manual_steps": [
                "Open Windows Security (Win+I → Privacy & Security → Windows Security)",
                "Click 'Firewall & network protection'",
                f"Click '{profile} network'",
                "Turn on Microsoft Defender Firewall",
            ],
            "auto_command":      f"Set-NetFirewallProfile -Profile {profile} -Enabled True",
            "verify_command":    f"(Get-NetFirewallProfile -Profile {profile}).Enabled",
            "verify_pass_value": "True",
        }

    # ── UAC disabled ─────────────────────────────────────────────────────────
    if fid == "uac_disabled":
        return {
            "can_auto":       True,
            "auto_label":     "Enable UAC via Registry",
            "action_summary": r"Sets HKLM\...\EnableLUA = 1 (same as dragging UAC slider to Notify).",
            "warning":        "A system RESTART is required after enabling UAC for the change to take effect.",
            "manual_steps": [
                "Press Win+R → type 'UserAccountControlSettings' → Enter",
                "Drag the slider to 'Notify me only when apps try to make changes'",
                "Click OK and restart your machine",
            ],
            "auto_command":
                r"Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' "
                r"-Name EnableLUA -Value 1",
            "verify_command":
                r"(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' "
                r"-Name EnableLUA).EnableLUA",
            "verify_pass_value": "1",
        }

    # ── Defender real-time off ────────────────────────────────────────────────
    if fid == "defender_realtime_off":
        return {
            "can_auto":       True,
            "auto_label":     "Re-enable Real-Time Protection",
            "action_summary": "Runs: Set-MpPreference -DisableRealtimeMonitoring $false",
            "warning":        None,
            "manual_steps": [
                "Open Windows Security → 'Virus & threat protection'",
                "Click 'Manage settings' under Virus & threat protection settings",
                "Toggle 'Real-time protection' ON",
            ],
            "auto_command":      "Set-MpPreference -DisableRealtimeMonitoring $false",
            "verify_command":    "(Get-MpComputerStatus).RealTimeProtectionEnabled",
            "verify_pass_value": "True",
        }

    # ── Defender signatures stale ─────────────────────────────────────────────
    if fid == "defender_sigs_stale":
        return {
            "can_auto":       True,
            "auto_label":     "Update Signatures Now",
            "action_summary": "Runs: Update-MpSignature — forces an immediate definition update.",
            "warning":        None,
            "manual_steps": [
                "Open Windows Security → Virus & threat protection",
                "Click 'Check for updates' under Virus & threat protection updates",
            ],
            "auto_command":      "Update-MpSignature",
            "verify_command":    "(Get-MpComputerStatus).AntivirusSignatureAge",
            "verify_pass_value": None,   # Any successful output = pass
        }

    # ── Open local port — add firewall block rule ────────────────────────────
    if fid.startswith("open_port_"):
        try:
            port = int(fid[len("open_port_"):])
        except ValueError:
            port = 0
        svc = RISKY_PORTS.get(port, (str(port), "LOW", ""))[0]
        rule_name = f"BoundryAI Block {svc} Port {port}"
        return {
            "can_auto":       True,
            "auto_label":     f"Add Firewall Block Rule (Port {port})",
            "action_summary": (
                f"Adds a Windows Firewall inbound BLOCK rule for TCP {port}. "
                f"The {svc} service will still be running — only inbound connections are blocked."
            ),
            "warning": (
                f"This blocks INBOUND connections on port {port} via the firewall. "
                f"It does NOT stop the {svc} service itself. "
                "To fully close this attack surface, also stop/disable the owning service."
            ),
            "manual_steps": [
                f"Add a firewall block (PowerShell as admin):",
                f"  New-NetFirewallRule -DisplayName '{rule_name}' "
                f"-Direction Inbound -LocalPort {port} -Protocol TCP -Action Block",
                "",
                "Then optionally stop the owning service:",
                f"  Get-NetTCPConnection -LocalPort {port} | Select OwningProcess",
                "  Use the PID to identify and stop/disable the service",
            ],
            "auto_command":
                f"New-NetFirewallRule -DisplayName '{rule_name}' "
                f"-Direction Inbound -LocalPort {port} -Protocol TCP -Action Block "
                f"-ErrorAction SilentlyContinue",
            "verify_command":
                f"(Get-NetFirewallRule -DisplayName '{rule_name}' "
                f"-ErrorAction SilentlyContinue).Enabled",
            "verify_pass_value": "True",
        }

    # ── Guest account enabled ─────────────────────────────────────────────────
    if fid == "guest_account_enabled":
        return {
            "can_auto":       True,
            "auto_label":     "Disable Guest Account",
            "action_summary": "Runs: Disable-LocalUser -Name Guest",
            "warning":        None,
            "manual_steps": [
                "Win+X → Computer Management → Local Users and Groups → Users",
                "Right-click 'Guest' → Properties",
                "Check 'Account is disabled' → OK",
            ],
            "auto_command":      "Disable-LocalUser -Name Guest",
            "verify_command":    "(Get-LocalUser -Name Guest).Enabled",
            "verify_pass_value": "False",
        }

    # ── Default admin account active ──────────────────────────────────────────
    if fid == "default_admin_active":
        return {
            "can_auto":       True,
            "auto_label":     "Disable Built-in Administrator",
            "action_summary": "Runs: Disable-LocalUser -Name Administrator",
            "warning":        (
                "Only do this if you have at least one other administrator account. "
                "Check first: Get-LocalGroupMember -Group Administrators"
            ),
            "manual_steps": [
                "First verify you have another admin account:",
                "  Get-LocalGroupMember -Group Administrators",
                "Then disable: Disable-LocalUser -Name Administrator",
                "OR rename it: Rename-LocalUser -Name Administrator -NewName <custom_name>",
            ],
            "auto_command":      "Disable-LocalUser -Name Administrator",
            "verify_command":    "(Get-LocalUser -Name Administrator).Enabled",
            "verify_pass_value": "False",
        }

    # ── Password never expires ────────────────────────────────────────────────
    if fid.startswith("pwd_never_expires_"):
        username = finding_id[len("pwd_never_expires_"):]
        return {
            "can_auto":       True,
            "auto_label":     f"Enable Password Expiry for {username}",
            "action_summary": f"Runs: Set-LocalUser -Name '{username}' -PasswordNeverExpires $false",
            "warning":        None,
            "manual_steps": [
                "Computer Management → Local Users and Groups → Users",
                f"Right-click '{username}' → Properties",
                "Uncheck 'Password never expires' → OK",
            ],
            "auto_command":      f"Set-LocalUser -Name '{username}' -PasswordNeverExpires $false",
            "verify_command":    f"(Get-LocalUser -Name '{username}').PasswordNeverExpires",
            "verify_pass_value": "False",
        }

    # ── Non-default SMB share active ──────────────────────────────────────────
    if fid.startswith("smb_share_"):
        share_name = finding_id[len("smb_share_"):]
        return {
            "can_auto":       True,
            "auto_label":     f"Remove Share '{share_name}'",
            "action_summary": f"Runs: Remove-SmbShare -Name '{share_name}' -Force",
            "warning":        (
                f"Permanently removes \\\\localhost\\{share_name}. "
                "Anyone currently connected will lose access immediately."
            ),
            "manual_steps": [
                "Computer Management → Shared Folders → Shares",
                f"Right-click '{share_name}' → Stop Sharing",
            ],
            "auto_command":      f"Remove-SmbShare -Name '{share_name}' -Force",
            "verify_command":    f"@(Get-SmbShare | Where-Object {{$_.Name -eq '{share_name}'}}).Count",
            "verify_pass_value": "0",
        }

    # ── Pending Windows updates — manual only ─────────────────────────────────
    if fid == "pending_windows_updates":
        return {
            "can_auto":       False,
            "auto_label":     None,
            "action_summary": "Windows updates cannot be auto-installed silently — manual install required.",
            "warning":        None,
            "manual_steps": [
                "Press Win+I → Windows Update",
                "Click 'Check for updates'",
                "Install all Critical and Important updates",
                "Restart if prompted",
                "Run the Machine Scan again to verify this finding is gone",
            ],
            "auto_command":      None,
            "verify_command":    (
                "(New-Object -ComObject Microsoft.Update.Session)"
                ".CreateUpdateSearcher().Search('IsInstalled=0 and Type=\\'Software\\'').Updates.Count"
            ),
            "verify_pass_value": "0",
        }

    # ── Network findings — remote device, manual only ────────────────────────
    if fid.startswith("net_"):
        return {
            "can_auto":       False,
            "auto_label":     None,
            "action_summary": "Network device — must be remediated directly on the target device.",
            "warning":        None,
            "manual_steps": [
                "Identify the device (check router admin panel for device list)",
                "Log into the device directly",
                "Disable or restrict the reported service",
                "Run Network Scan again to verify",
            ],
            "auto_command":      None,
            "verify_command":    None,
            "verify_pass_value": None,
        }

    # ── Default fallback ──────────────────────────────────────────────────────
    return {
        "can_auto":       False,
        "auto_label":     None,
        "action_summary": "Manual remediation required — follow the recommendation below.",
        "warning":        None,
        "manual_steps":   ["Follow the recommendation shown in the finding details."],
        "auto_command":   None,
        "verify_command": None,
        "verify_pass_value": None,
    }


def verify_finding_fixed(finding_id):
    """
    Re-run the verification check for a finding_id.
    Returns (is_fixed: bool, output: str).
    """
    plan    = get_remediation_plan(finding_id)
    cmd     = plan.get("verify_command")
    if not cmd:
        return (True, "No verification available.")

    output   = _run_ps(cmd, timeout=20).strip()
    expected = plan.get("verify_pass_value")

    if expected is None:
        is_fixed = bool(output) and "error" not in output.lower()
    else:
        is_fixed = expected.lower() in output.lower()

    return (is_fixed, output)


def run_network_scan():
    """
    Discover live devices on the local /24 network and scan top ports.
    Returns a list of finding dicts for risky services found.
    Max 30 seconds — does a quick ARP-style TCP probe first, then port scan.
    """
    findings = []
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    subnet_str, local_ip = _get_local_subnet()
    network   = ipaddress.IPv4Network(subnet_str)
    all_hosts = [str(h) for h in network.hosts()]

    # Phase 1 — quick alive check (threaded, 0.5s timeout)
    alive_hosts = []
    lock        = threading.Lock()
    threads     = []
    for ip in all_hosts[:254]:
        t = threading.Thread(target=_ping_host, args=(ip, alive_hosts, lock))
        t.daemon = True
        threads.append(t)
        t.start()
    for t in threads:
        t.join(timeout=2.0)

    # Always include router (x.x.x.1) even if it didn't respond
    router_ip = str(list(network.hosts())[0])
    if router_ip not in alive_hosts:
        alive_hosts.insert(0, router_ip)

    # Phase 2 — port scan alive hosts (skip local machine itself)
    for ip in alive_hosts:
        if ip == local_ip:
            continue
        open_ports = _scan_ports(ip, timeout=0.8)

        if not open_ports:
            continue

        # Generate findings for risky ports
        for port in open_ports:
            if port in RISKY_PORTS:
                service, severity, detail = RISKY_PORTS[port]
                if severity in ("CRITICAL", "HIGH", "MEDIUM"):
                    findings.append(_make_finding(
                        finding_id=f"net_{ip.replace('.','_')}_{port}",
                        title=f"{ip}: Port {port} ({service}) exposed on network",
                        severity=severity,
                        category="network_device",
                        description=(
                            f"Device {ip} has {service} (port {port}) open on your local network. "
                            f"{detail} "
                            "CISSP Domain 4 — Communication & Network Security: "
                            "all network-exposed services must be inventoried and assessed."
                        ),
                        recommendation=(
                            f"Identify the device at {ip}. "
                            f"Verify that {service} on port {port} is necessary and properly secured. "
                            "If the service is not needed, disable it on the device."
                        ),
                        raw_output=f"Host: {ip}, Open ports: {open_ports}",
                    ))

        # Add an INFO-level device found entry if the device has any open port
        findings.append(_make_finding(
            finding_id=f"net_device_{ip.replace('.','_')}",
            title=f"Network device discovered: {ip}",
            severity="INFO",
            category="network_device",
            description=(
                f"A device at {ip} responded on the network with these ports open: "
                f"{', '.join(str(p) for p in open_ports)}. "
                "CISSP Domain 4: network asset inventory is the foundation of network security. "
                "Every device on your network should be known, catalogued, and managed."
            ),
            recommendation=(
                f"Verify: what is the device at {ip}? "
                "Add it to your asset inventory. "
                "Ensure it runs supported, patched firmware/OS."
            ),
            raw_output=f"Host: {ip}, Open ports: {open_ports}",
        ))

    findings.sort(key=lambda f: severity_order.get(f["severity"], 5))
    return findings
