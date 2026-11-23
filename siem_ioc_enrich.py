"""
On-demand SIEM IOC extraction + offline stub enrichment (Stage 6b).

Uses soc_ioc_stub.lookup_ioc only — no outbound HTTP.
"""

from __future__ import annotations

import json
import re
from typing import Any

import soc_ioc_stub
import soc_lab

_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)
_DOMAIN = re.compile(
    r"\b(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})\b",
    re.I,
)
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")


def defang_ip(value: str) -> str:
    """Defang IPv4 for ticket paste."""
    return value.replace(".", "[.]")


def defang_domain(value: str) -> str:
    """Defang domain dots."""
    return value.replace(".", "[.]")


def defang_for_kind(kind: str, value: str) -> str:
    """Return defanged string for ip/domain/hash (hash unchanged)."""
    if kind == "ip":
        return defang_ip(value)
    if kind == "domain":
        return defang_domain(value)
    return value


def _add_indicator(
    bucket: list[dict[str, str]],
    seen: set[str],
    kind: str,
    value: str,
) -> None:
    v = (value or "").strip()
    if not v:
        return
    key = f"{kind}:{v.lower()}"
    if key in seen:
        return
    seen.add(key)
    bucket.append({"kind": kind, "value": v})


def extract_indicators_from_event(
    row: dict[str, Any],
    raw_parsed: Any,
    observables_entities: list[dict[str, str]] | None = None,
) -> list[dict[str, str]]:
    """Collect IOC-shaped values from a SIEM event row and optional observables."""
    indicators: list[dict[str, str]] = []
    seen: set[str] = set()

    for entity in observables_entities or []:
        kind = (entity.get("kind") or "").lower()
        val = entity.get("value") or ""
        if kind == "ip":
            _add_indicator(indicators, seen, "ip", val)
        elif kind in ("domain", "host") and "." in val and " " not in val:
            _add_indicator(indicators, seen, "domain", val.lower())

    if row.get("src_ip"):
        _add_indicator(indicators, seen, "ip", row["src_ip"])
    if row.get("dst_ip"):
        _add_indicator(indicators, seen, "ip", row["dst_ip"])

    desc = row.get("description") or ""
    for ip in soc_lab._ips_from_text(desc):
        _add_indicator(indicators, seen, "ip", ip)

    blob = desc
    if raw_parsed is not None:
        try:
            blob += " " + json.dumps(raw_parsed)
        except (TypeError, ValueError):
            blob += " " + str(raw_parsed)
    elif row.get("raw_data"):
        blob += " " + str(row.get("raw_data"))

    for ip in _IPV4.findall(blob):
        _add_indicator(indicators, seen, "ip", ip)
    for dom in _DOMAIN.findall(blob):
        dl = dom.lower()
        if dl.count(".") >= 1 and len(dl) < 120:
            _add_indicator(indicators, seen, "domain", dl)
    for h in _SHA256.findall(blob):
        _add_indicator(indicators, seen, "sha256", h.lower())

    return indicators


def enrich_indicators(indicators: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Run offline stub lookup for each indicator."""
    rows: list[dict[str, Any]] = []
    for ind in indicators:
        lookup = soc_ioc_stub.lookup_ioc(ind["value"])
        rows.append(
            {
                "indicator": ind["value"],
                "kind": ind["kind"],
                "defanged": defang_for_kind(ind["kind"], ind["value"]),
                "found": lookup.get("found"),
                "verdict": lookup.get("verdict"),
                "score": lookup.get("score"),
                "summary": lookup.get("summary"),
                "tags": lookup.get("tags") or [],
                "ioc_type": lookup.get("ioc_type"),
            }
        )
    return rows


def plain_language_summary(enrichment: list[dict[str, Any]]) -> str:
    """One sentence for analysts (offline stub context)."""
    if not enrichment:
        return "No indicators to enrich on this event."
    malicious = [e for e in enrichment if e.get("verdict") == "malicious"]
    suspicious = [e for e in enrichment if e.get("verdict") == "suspicious"]
    if malicious:
        sample = ", ".join(e["indicator"] for e in malicious[:2])
        extra = f" (+{len(malicious) - 2} more)" if len(malicious) > 2 else ""
        return (
            f"Practice stub marks {len(malicious)} indicator(s) malicious ({sample}{extra}). "
            "Confirm with policy and a second source before block or escalation."
        )
    if suspicious:
        return (
            f"Practice stub shows {len(suspicious)} suspicious indicator(s). "
            "Treat as lead only; correlate with this event and user context."
        )
    unknown = sum(1 for e in enrichment if e.get("verdict") == "unknown")
    if unknown == len(enrichment):
        return (
            "No stub records for these indicators. "
            "In production you would query threat intel; here, document unknown and escalate if severity warrants."
        )
    return "Stub shows benign or mixed context. Use event severity and user story before close."


def build_enrich_payload(
    indicators: list[dict[str, str]],
    *,
    event_id: int | None = None,
) -> dict[str, Any]:
    """Full API response body for enrich."""
    enrichment = enrich_indicators(indicators)
    defanged_map = {row["indicator"]: row["defanged"] for row in enrichment}
    return {
        "ok": True,
        "source": "local_stub",
        "event_id": event_id,
        "indicators_found": indicators,
        "enrichment": enrichment,
        "defanged": defanged_map,
        "plain_summary": plain_language_summary(enrichment),
    }