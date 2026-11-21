"""
G9 — Networking for analysts (Net-for-SOC).

Flashcards + signal drills that pair with the Learn spine in net_learn.py /
net_lessons.py. Analyst networking course (SOC-focused, not CCNA).
Original Boundry scenarios only. Terms defined before use.
"""

from __future__ import annotations

from typing import Any

import career_instances
import career_rationale

TRACK_TITLE = "Networking for Analysts"
TRACK_BLURB = (
    "Analyst networking course (SOC-focused, not CCNA). Learn the network facts "
    "SOC Tier-1 cites in tickets: ports that matter, what DNS and HTTP prove, "
    "traffic direction, and how to turn a snippet into enrich / escalate / close. "
    "Show me → Help me → Prove it, plus flashcards and signal drills on this hub."
)

PASS_PCT = 70

PRIMER = [
    {
        "term": "Port",
        "plain": "A number on a host that names which service is talking (example: 443 often means HTTPS). Analysts cite port + protocol in tickets.",
    },
    {
        "term": "Protocol",
        "plain": "The language of the packet (TCP, UDP, ICMP, DNS, HTTP/HTTPS). Wrong protocol labels confuse the next analyst.",
    },
    {
        "term": "DNS",
        "plain": "Domain Name System: translates a name like login.contoso.com into an IP address. SOC often sees DNS queries before the bad download.",
    },
    {
        "term": "East-west traffic",
        "plain": "Traffic between hosts inside the same network (workstation to workstation, or workstation to internal server). Different from outbound internet (north-south / egress).",
    },
    {
        "term": "Egress",
        "plain": "Outbound traffic leaving the org network toward the internet. Odd egress ports are a common L1 alert pattern.",
    },
]

# Flashcards shown on the hub (Show me)
FLASHCARDS: list[dict[str, str]] = [
    {
        "front": "TCP 22",
        "back": "SSH. Remote admin shell. Unexpected 22 from internet or between workstations deserves a ticket note.",
    },
    {
        "front": "TCP 3389",
        "back": "RDP. Remote Desktop. Lateral movement screening often starts here (plus 445 for SMB).",
    },
    {
        "front": "TCP 445",
        "back": "SMB. File/share and many Windows admin tools. East-west SMB bursts can mean lateral movement or backup noise. Document both ends.",
    },
    {
        "front": "TCP 443 / 80",
        "back": "HTTPS / HTTP. Web traffic. Cite URL or SNI/host when you have it. Port alone does not prove malware.",
    },
    {
        "front": "UDP/TCP 53",
        "back": "DNS. Name lookups. A workstation querying a rare domain before a download is classic pre-exfil / C2 setup evidence.",
    },
    {
        "front": "TCP 25 / 587",
        "back": "SMTP mail submission. Unexpected workstation → internet:25 can mean a spam bot (policy dependent).",
    },
    {
        "front": "Non-standard high port (e.g. 4444, 8080)",
        "back": "Often tools, proxies, or reverse shells. Not proof alone. Pair with process, destination reputation, and volume.",
    },
    {
        "front": "HTTP status 200 vs 302",
        "back": "200 = response body delivered. 302 = redirect. A phish click that returns 200 means the page (or payload) was served.",
    },
]


def _drill(
    did: str,
    title: str,
    difficulty: int,
    signal_id: str,
    direction_id: str,
    teach: str,
    snippet: str,
    checklist: dict[str, bool],
) -> dict[str, Any]:
    return {
        "id": did,
        "title": title,
        "difficulty": difficulty,
        "correct_signal": signal_id,
        "correct_direction": direction_id,
        "teach": teach,
        "snippet": snippet.strip() + "\n",
        "checklist_answers": checklist,
    }


DRILLS: list[dict[str, Any]] = [
    _drill(
        "egress_4444",
        "Workstation to rare TCP 4444",
        1,
        "rare_egress_port",
        "egress_internet",
        "Internal host to an internet IP on an uncommon port is egress worth enriching. Port 4444 is a classic tool/listener pattern, not proof of malware alone.",
        """
src=10.20.30.55 dst=198.51.100.77 proto=TCP sport=51884 dport=4444
action=ALLOW (or DENY in some environments)
note=firewall/proxy saw first packet toward documentation TEST-NET
""",
        {
            "cites_dst_port": True,
            "dns_query_primary": False,
            "east_west_pattern": False,
            "http_status_cited": False,
        },
    ),
    _drill(
        "dns_before_download",
        "DNS lookup then HTTP GET",
        1,
        "dns_then_http",
        "egress_internet",
        "DNS proves the name was resolved. Pair with the later HTTP/HTTPS request. Cite query name + destination IP when both appear.",
        """
14:01:02 DNS query name=update.c0ntoso-finance.com type=A client=10.20.30.88 → 203.0.113.88
14:01:04 HTTP GET http://203.0.113.88/u.exe status=200 bytes=482112
host=WS-HR-03 user=j.patel
""",
        {
            "cites_dst_port": False,
            "dns_query_primary": True,
            "east_west_pattern": False,
            "http_status_cited": True,
        },
    ),
    _drill(
        "rdp_lateral",
        "RDP between workstations",
        2,
        "rdp_3389",
        "east_west",
        "TCP 3389 between two internal hosts is east-west remote desktop. Ticket src, dst, and whether the account is expected for admin work.",
        """
src=10.20.30.12 (WS-IT-02) dst=10.20.30.77 (WS-FINANCE-12)
proto=TCP dport=3389 action=ALLOW
user_hint=svc_helpdesk (or unknown)
""",
        {
            "cites_dst_port": True,
            "dns_query_primary": False,
            "east_west_pattern": True,
            "http_status_cited": False,
        },
    ),
    _drill(
        "smb_east_west",
        "SMB burst across subnet",
        2,
        "smb_445",
        "east_west",
        "TCP 445 east-west can be backup, admin tools, or lateral movement. Document both ends and volume. Do not invent malware without host evidence.",
        """
src=10.20.40.9 dst=10.20.40.15,10.20.40.16,10.20.40.18
proto=TCP dport=445 count=140 in 3m
label=internal file-share / admin path (confirm with host team)
""",
        {
            "cites_dst_port": True,
            "dns_query_primary": False,
            "east_west_pattern": True,
            "http_status_cited": False,
        },
    ),
    _drill(
        "http_phish_200",
        "Proxy allow with HTTP 200",
        2,
        "http_web",
        "egress_internet",
        "HTTP/HTTPS egress with status 200 means content was returned. Cite URL, user, and status. Port 443 alone is not the story.",
        """
user=ap.clerk@clientcorp.example method=GET
url=https://c0ntoso-finance.com/wire-approve
dport=443 http_status=200 action=ALLOW
""",
        {
            "cites_dst_port": True,
            "dns_query_primary": False,
            "east_west_pattern": False,
            "http_status_cited": True,
        },
    ),
    _drill(
        "ssh_ingress_bruteforce",
        "Internet SSH to jump box",
        1,
        "ssh_22",
        "ingress_internet",
        "TCP 22 from the internet toward a jump host is ingress. Ticket source volume and whether the jump box should be internet-exposed at all.",
        """
src=198.51.100.200 dst=203.0.113.10 (JUMP-DMZ-01)
proto=TCP dport=22 count=220 fails in 10m action=DENY then 1 ALLOW
note=edge firewall + auth log pair
""",
        {
            "cites_dst_port": True,
            "dns_query_primary": False,
            "east_west_pattern": False,
            "http_status_cited": False,
        },
    ),
    _drill(
        "dns_tunnel_hint",
        "High-volume weird DNS labels",
        2,
        "dns_then_http",
        "egress_internet",
        "Long random DNS labels to a rare domain can be tunneling or beaconing. Cite the query names and client host; pair with proxy/HTTP if present.",
        """
14:22:01 DNS query name=a8f3c1.d9e2b7.update-cdn-check.net type=TXT client=10.20.30.55
14:22:02 DNS query name=b1c0ee.11aa22.update-cdn-check.net type=TXT client=10.20.30.55
count=180 TXT queries in 5m to same parent domain
no matching HTTP yet
""",
        {
            "cites_dst_port": False,
            "dns_query_primary": True,
            "east_west_pattern": False,
            "http_status_cited": False,
        },
    ),
    _drill(
        "rdp_ingress_edge",
        "RDP exposed on edge (ingress)",
        2,
        "rdp_3389",
        "ingress_internet",
        "TCP 3389 from internet to a DMZ jump box is ingress remote desktop, not east-west. That exposure itself is a finding.",
        """
src=45.77.12.200 dst=203.0.113.10 (JUMP-DMZ-01)
proto=TCP dport=3389 action=ALLOW
note=edge NAT publishes 3389 — confirm with network owner
""",
        {
            "cites_dst_port": True,
            "dns_query_primary": False,
            "east_west_pattern": False,
            "http_status_cited": False,
        },
    ),
]

SIGNALS = [
    {
        "id": "rare_egress_port",
        "label": "Odd / rare outbound destination port (e.g. 4444)",
    },
    {
        "id": "dns_then_http",
        "label": "DNS name lookup followed by HTTP(S) fetch",
    },
    {
        "id": "rdp_3389",
        "label": "Remote Desktop (TCP 3389)",
    },
    {
        "id": "smb_445",
        "label": "SMB / file share (TCP 445)",
    },
    {
        "id": "http_web",
        "label": "Web HTTP(S) request (80/443) with URL/status",
    },
    {
        "id": "ssh_22",
        "label": "SSH remote shell (TCP 22)",
    },
]

DIRECTIONS = [
    {
        "id": "egress_internet",
        "label": "Egress / north-south (internal host → internet)",
    },
    {
        "id": "east_west",
        "label": "East-west (internal host → internal host)",
    },
    {
        "id": "ingress_internet",
        "label": "Ingress (internet → internal host)",
    },
]

CHECKLIST_ITEMS = [
    {
        "id": "cites_dst_port",
        "label": "Snippet clearly shows a destination port (dport) worth citing",
    },
    {
        "id": "dns_query_primary",
        "label": "Primary story starts with a DNS query name (not only a raw IP)",
    },
    {
        "id": "east_west_pattern",
        "label": "Both source and destination look internal (east-west pattern)",
    },
    {
        "id": "http_status_cited",
        "label": "Snippet includes an HTTP status code (e.g. 200) worth citing",
    },
]


def drill_ids() -> list[str]:
    """Ordered drill ids for next-scenario rotation."""
    return [d["id"] for d in DRILLS]


def list_drills() -> list[dict[str, Any]]:
    """Hub cards without snippets."""
    return [
        {
            "id": d["id"],
            "title": d["title"],
            "difficulty": d["difficulty"],
            "teach": d["teach"],
        }
        for d in DRILLS
    ]


def get_drill(drill_id: str) -> dict[str, Any] | None:
    """Return one drill including snippet (canonical, no variants)."""
    for d in DRILLS:
        if d["id"] == drill_id:
            return d
    return None


def materialize_drill(drill_id: str, seed: str | None = None) -> dict[str, Any] | None:
    """Variant instance: new hosts/IPs in the flow snippet."""
    drill = get_drill(drill_id)
    if not drill:
        return None
    return career_instances.materialize_generic(
        drill,
        seed,
        host_key=None,
        user_key=None,
        text_keys=["snippet", "teach"],
        allow_ip=True,
    )


def next_after(drill_id: str) -> dict[str, str]:
    """Random different drill + fresh seed under /career/net."""
    return career_instances.next_scenario(drill_ids(), drill_id, "/career/net")


def grade_drill(
    drill_id: str,
    signal_id: str,
    direction_id: str,
    checklist: dict[str, bool],
) -> dict[str, Any]:
    """Grade network signal + traffic direction + checklist."""
    drill = get_drill(drill_id)
    if not drill:
        return {"ok": False, "error": "Unknown drill"}
    answers = drill["checklist_answers"]
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
    signal_ok = (signal_id or "").strip() == drill["correct_signal"]
    direction_ok = (direction_id or "").strip() == drill["correct_direction"]
    # Checklist 4 + signal 2 + direction 2
    score = hit + (2 if signal_ok else 0) + (2 if direction_ok else 0)
    total = len(CHECKLIST_ITEMS) + 4
    pct = round(100 * score / total)
    sig_meta = next((s for s in SIGNALS if s["id"] == drill["correct_signal"]), None)
    dir_meta = next(
        (d for d in DIRECTIONS if d["id"] == drill["correct_direction"]), None
    )
    return {
        "ok": True,
        "pct": pct,
        "passed": pct >= PASS_PCT,
        "checklist": items,
        "signal_correct": signal_ok,
        "correct_signal": drill["correct_signal"],
        "direction_correct": direction_ok,
        "correct_direction": drill["correct_direction"],
        "teach": drill["teach"],
        "score": score,
        "total": total,
        "answer_chips": [
            career_rationale.chip(
                id="signal",
                label=(sig_meta or {}).get("label") or drill["correct_signal"],
                matched=signal_ok,
                rationale=f"For this drill: {drill['teach']}",
                title="Why this network signal",
                row_label="Correct signal",
            ),
            career_rationale.chip(
                id="direction",
                label=(dir_meta or {}).get("label") or drill["correct_direction"],
                matched=direction_ok,
                rationale=f"Traffic direction matters for triage. For this drill: {drill['teach']}",
                title="Why this direction",
                row_label="Correct direction",
            ),
        ],
    }
