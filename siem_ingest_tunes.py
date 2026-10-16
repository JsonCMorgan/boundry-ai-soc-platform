"""
SIEM ingest tunes — reduce false-positive correlation without hiding audit trail.

How to add a Windows event tune:
  1. Add a matcher (regex or event id check) in tune_windows_event().
  2. Return TuneResult(event_type, severity, description_prefix, correlate=False).
  3. Keep correlate=True for anything that should still fire siem_rules.

Firewall drops use classify_firewall_drop() so internet background scans do not
count toward the Firewall Port Scan correlation rule.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Optional

# Destination ports that matter on a home analyst workstation (edge-targeted).
RISKY_DST_PORTS = frozenset(
    {"22", "23", "3389", "445", "135", "139", "1433", "3306", "5432", "5900", "6379"}
)

_BENIGN_SERVICE_RE = re.compile(
    r"(Service Name:\s*NEP[A-Za-z0-9]+)"
    r"|(NordVPN)"
    r"|(NordLynx)"
    r"|(nordsec)"
    r"|(\\Program Files\\NordVPN\\)"
    r"|(\\Program Files \(x86\)\\NordVPN\\)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class TuneResult:
    """Override fields applied before ingest_event()."""

    event_type: str
    severity: str
    description_prefix: str
    correlate: bool


def _parse_ipv4(addr: str) -> Optional[ipaddress.IPv4Address]:
    """Parse IPv4 or return None on failure."""
    try:
        return ipaddress.ip_address((addr or "").strip())
    except ValueError:
        return None


def _is_public_source(src_ip: str) -> bool:
    """True when source is a routable public IPv4 (internet scanner)."""
    ip = _parse_ipv4(src_ip)
    if ip is None or not isinstance(ip, ipaddress.IPv4Address):
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
    )


def classify_firewall_drop(
    src_ip: str, dst_ip: str, dst_port: str
) -> tuple[str, str, bool]:
    """
    Return (severity, event_type, correlate) for a firewall DROP line.

    Public internet scanners hitting non-risky ports → INFO background, no correlation.
    """
    port = (dst_port or "").strip()
    risky = port in RISKY_DST_PORTS
    public_src = _is_public_source(src_ip)

    if public_src and not risky:
        return ("INFO", "firewall_block_background", False)

    if public_src and risky:
        return ("HIGH", "firewall_block", True)

    # LAN / private source — more suspicious than random internet noise
    if risky:
        return ("HIGH", "firewall_block", True)
    return ("MEDIUM", "firewall_block", True)


def tune_windows_event(event_id: int, message: str) -> Optional[TuneResult]:
    """
    Return a TuneResult when this Windows event should be softened at ingest.
    None means use the default _WIN_EVENT_MAP severity/type.
    """
    msg = message or ""

    if event_id == 7045 and _BENIGN_SERVICE_RE.search(msg):
        return TuneResult(
            event_type="service_installed_benign",
            severity="INFO",
            description_prefix="Event 7045 [tuned vendor noise]",
            correlate=False,
        )

    return None
