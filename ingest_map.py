"""Map /api/ingest event_type strings to SIEM event_type + severity."""

from __future__ import annotations

INGEST_SIEM_MAP: dict[str, tuple[str, str]] = {
  # Legacy app / training types
    "LOGIN_FAILED": ("logon_failed", "MEDIUM"),
    "LOGIN_SUCCESS": ("logon_success", "INFO"),
    "SEARCH": ("scan_initiated", "LOW"),
    "REGISTER_SUCCESS": ("account_created", "LOW"),
    "XSS_ATTEMPT": ("api_unauthorized", "HIGH"),
    "DIRECTORY_TRAVERSAL": ("api_unauthorized", "HIGH"),
    "PRIV_ESC_ATTEMPT": ("special_privilege_logon", "HIGH"),
    "ACCOUNT_ENUM": ("logon_failed", "MEDIUM"),
    # Professional-services (GAP-019)
    "M365_SIGNIN_FAILED": ("m365_signin_failed", "MEDIUM"),
    "M365_IMPOSSIBLE_TRAVEL": ("m365_impossible_travel", "HIGH"),
    "FILE_DOWNLOAD_ANOMALY": ("file_download_anomaly", "HIGH"),
    "VENDOR_APP_CONSENT": ("vendor_app_consent", "HIGH"),
}

VALID_INGEST_TYPES = frozenset(INGEST_SIEM_MAP.keys())


def siem_mapping(event_type: str) -> tuple[str, str]:
    """Return (siem_event_type, severity) for an ingest event_type."""
    key = (event_type or "").upper()
    return INGEST_SIEM_MAP.get(key, ("ingest_generic", "MEDIUM"))