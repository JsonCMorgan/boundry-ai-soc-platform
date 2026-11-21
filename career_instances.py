"""
Career hands-on lab instances — variant surface fields + next-scenario routing.

Teaching keys (correct_* / checklist_answers / note_must_include) stay stable.
Each open can swap hosts, users, paths, IPs, filenames, and ticket IDs so the
same pattern does not look identical every time.
"""

from __future__ import annotations

import copy
import hashlib
import random
import re
import secrets
from typing import Any

# Keys that must never be rewritten when applying surface variants.
STABLE_KEYS: frozenset[str] = frozenset({
    "id",
    "difficulty",
    "checklist_answers",
    "correct_isolate",
    "correct_disposition",
    "correct_source",
    "correct_evidence",
    "correct_signal",
    "correct_direction",
    "correct_priority",
    "correct_blade",
    "correct_outcome",
    "note_must_include",
    "instance_seed",
})

# Documentation / practice ranges and common lab surface banks.
HOST_BANK: list[str] = [
    "WS-HR-03",
    "WS-HR-11",
    "WS-FINANCE-12",
    "WS-FINANCE-08",
    "WS-MKT-07",
    "WS-MKT-14",
    "WS-OPS-02",
    "WS-OPS-19",
    "WS-SALES-04",
    "WS-IT-02",
    "WS-IT-21",
    "LAPTOP-ENG-06",
    "JUMP-DMZ-01",
    "JUMP-DMZ-03",
    "DC01",
    "DC02",
    "NP-LAPTOP-18",
    "NP-LAPTOP-22",
]

USER_BANK: list[str] = [
    "j.patel",
    "a.chen",
    "m.okonkwo",
    "s.reid",
    "a.morgan",
    "c.lee",
    "r.nguyen",
    "t.brooks",
    "k.hassan",
    "helpdesk.svc",
    "svc_helpdesk",
    "ap.clerk",
]

# TEST-NET style addresses (practice only). Prefer swapping within the same /24 family.
IP_BANK: list[str] = [
    "203.0.113.44",
    "203.0.113.55",
    "203.0.113.77",
    "203.0.113.88",
    "203.0.113.91",
    "198.51.100.12",
    "198.51.100.40",
    "198.51.100.77",
    "198.51.100.90",
    "10.20.30.12",
    "10.20.30.55",
    "10.20.30.77",
    "10.20.30.88",
]

FILENAME_BANK: list[str] = [
    "Invoice_44102.xlsm",
    "Remit_Advice_8821.xlsm",
    "PO_Update_11904.xlsx",
    "Q3_Budget_Review.xlsm",
    "Vendor_W9_scan.pdf",
    "CollectDiag.ps1",
    "HostHealthCheck.ps1",
    "u.exe",
    "payload.bin",
    "upd.hta",
    "a.ps1",
]

TICKET_BANK: list[str] = [
    "INC-8821",
    "INC-9104",
    "INC-7740",
    "INC-12033",
    "CHG-4401",
    "CHG-5518",
    "TKT-3088",
    "TKT-6621",
]

MSGID_BANK: list[str] = [
    "bec001@c0ntoso-finance.com",
    "wire8821@c0ntoso-finance.com",
    "ap-notice@hr.clientcorp.example",
    "payupd@secure-payroll.example",
    "vendor-w9@mail.example",
]

AMOUNT_BANK: list[str] = [
    "$48,500",
    "$52,750",
    "$37,200",
    "$61,400",
    "$29,900",
]

BANKS: dict[str, list[str]] = {
    "host": HOST_BANK,
    "user": USER_BANK,
    "ip": IP_BANK,
    "filename": FILENAME_BANK,
    "ticket": TICKET_BANK,
    "msgid": MSGID_BANK,
    "amount": AMOUNT_BANK,
}

_IP_RE = re.compile(
    r"\b(?:203\.0\.113\.\d{1,3}|198\.51\.100\.\d{1,3}|10\.20\.30\.\d{1,3})\b"
)
_TICKET_RE = re.compile(r"\b(?:INC|CHG|TKT)-\d{3,6}\b", re.IGNORECASE)
_FILENAME_RE = re.compile(
    r"\b[\w.-]+\.(?:xlsm|xlsx|pdf|ps1|exe|hta|bin)\b", re.IGNORECASE
)
_AMOUNT_RE = re.compile(r"\$\d{1,3}(?:,\d{3})+")
_MSGID_RE = re.compile(r"(?<=Message-ID: <)[^>]+", re.IGNORECASE)


def new_seed() -> str:
    """Return a short hex seed for ?seed= URLs."""
    return secrets.token_hex(4)


def normalize_seed(raw: str | None) -> str:
    """Normalize a seed string; generate one if missing or invalid."""
    s = (raw or "").strip().lower()
    if re.fullmatch(r"[0-9a-f]{4,16}", s):
        return s
    return new_seed()


def rng_for(seed: str | None) -> random.Random:
    """Deterministic RNG from a seed string."""
    norm = normalize_seed(seed)
    digest = hashlib.sha256(norm.encode("utf-8")).hexdigest()
    return random.Random(int(digest[:16], 16))


def pick_next_case_id(
    pool: list[str],
    last_id: str | None,
    rng: random.Random | None = None,
) -> str:
    """Pick a case/drill id from pool, avoiding last_id when more than one exists."""
    ids = [str(x) for x in pool if x]
    if not ids:
        raise ValueError("Empty case pool")
    r = rng or random.Random()
    if len(ids) == 1:
        return ids[0]
    choices = [i for i in ids if i != (last_id or "")]
    if not choices:
        choices = ids
    return r.choice(choices)


def apply_variant_tokens(
    obj: Any,
    mapping: dict[str, str],
    *,
    skip_keys: frozenset[str] | None = None,
) -> Any:
    """Deep-copy obj applying longest-first string replacements. Skip stable keys."""
    if not mapping:
        return copy.deepcopy(obj)
    skip = skip_keys if skip_keys is not None else STABLE_KEYS
    ordered = sorted(mapping.keys(), key=len, reverse=True)

    def walk(node: Any, parent_key: str | None = None) -> Any:
        if parent_key in skip:
            return copy.deepcopy(node)
        if isinstance(node, str):
            out = node
            for old in ordered:
                new = mapping[old]
                if old and new and old != new:
                    out = out.replace(old, new)
            return out
        if isinstance(node, list):
            return [walk(x, parent_key) for x in node]
        if isinstance(node, dict):
            return {k: walk(v, k) for k, v in node.items()}
        return copy.deepcopy(node)

    return walk(obj)


def _pick_other(bank: list[str], current: str, rng: random.Random) -> str:
    """Pick a bank value different from current when possible."""
    cur = (current or "").strip()
    others = [b for b in bank if b.lower() != cur.lower()]
    if not others:
        return cur or (bank[0] if bank else "")
    return rng.choice(others)


def build_mapping(
    pairs: list[tuple[str, str]],
    rng: random.Random,
) -> dict[str, str]:
    """
    Build old→new replacements from (value, kind) pairs.

    kinds: host | user | ip | filename | ticket | msgid | amount
    """
    mapping: dict[str, str] = {}
    used_new: set[str] = set()
    for value, kind in pairs:
        old = (value or "").strip()
        if not old or old in mapping:
            continue
        bank = BANKS.get(kind) or []
        if not bank:
            continue
        # Prefer unused new values so one instance does not collide.
        candidates = [
            b for b in bank
            if b.lower() != old.lower() and b.lower() not in used_new
        ]
        if not candidates:
            candidates = [b for b in bank if b.lower() != old.lower()]
        if not candidates:
            continue
        new = rng.choice(candidates)
        mapping[old] = new
        used_new.add(new.lower())
    return mapping


def discover_text_surface(text: str, *, allow_ip: bool = True) -> list[tuple[str, str]]:
    """Find common surface tokens in free text (IPs, tickets, filenames, amounts)."""
    if not text:
        return []
    found: list[tuple[str, str]] = []
    if allow_ip:
        for m in _IP_RE.findall(text):
            found.append((m, "ip"))
    for m in _TICKET_RE.findall(text):
        found.append((m, "ticket"))
    for m in _FILENAME_RE.findall(text):
        found.append((m, "filename"))
    for m in _AMOUNT_RE.findall(text):
        found.append((m, "amount"))
    for m in _MSGID_RE.findall(text):
        found.append((m, "msgid"))
    return found


def remap_pids(tree: list[dict[str, Any]], rng: random.Random) -> list[dict[str, Any]]:
    """Assign fresh PIDs while preserving parent/child relationships."""
    if not tree:
        return []
    old_pids = [int(n["pid"]) for n in tree]
    used: set[int] = set()
    mapping: dict[int, int] = {}
    for old in old_pids:
        while True:
            # Keep PIDs in a realistic Windows range.
            cand = rng.randint(1200, 9800)
            if cand not in used and cand not in old_pids:
                used.add(cand)
                mapping[old] = cand
                break
    out: list[dict[str, Any]] = []
    for node in tree:
        n = dict(node)
        old_pid = int(n["pid"])
        old_ppid = int(n.get("ppid") or 0)
        n["pid"] = mapping.get(old_pid, old_pid)
        if old_ppid in mapping:
            n["ppid"] = mapping[old_ppid]
        out.append(n)
    return out


def next_scenario(
    pool: list[str],
    last_id: str | None,
    path_prefix: str,
    rng: random.Random | None = None,
) -> dict[str, str]:
    """
    Build next-scenario navigation payload.

    path_prefix example: /career/edr (no trailing slash)
    """
    r = rng or random.Random()
    nid = pick_next_case_id(pool, last_id, r)
    seed = new_seed()
    prefix = path_prefix.rstrip("/")
    return {
        "case_id": nid,
        "seed": seed,
        "url": f"{prefix}/{nid}?seed={seed}",
    }


def open_url(path_prefix: str, case_id: str, seed: str | None = None) -> str:
    """Hub/open URL with a fresh (or provided) instance seed."""
    s = normalize_seed(seed)
    return f"{path_prefix.rstrip('/')}/{case_id}?seed={s}"


def attach_open_urls(
    cards: list[dict[str, Any]],
    path_prefix: str,
    id_key: str = "id",
) -> list[dict[str, Any]]:
    """Copy hub cards and add open_url with a unique seed each."""
    out: list[dict[str, Any]] = []
    for card in cards:
        c = dict(card)
        cid = str(c.get(id_key) or "")
        c["open_url"] = open_url(path_prefix, cid)
        out.append(c)
    return out


def materialize_generic(
    case: dict[str, Any],
    seed: str | None,
    *,
    host_key: str | None = "host",
    user_key: str | None = "user",
    text_keys: list[str] | None = None,
    allow_ip: bool = True,
    remap_tree_pids: bool = False,
) -> dict[str, Any]:
    """
    Materialize a case/drill instance with variant surface fields.

    Grading still uses the original case id + stable answer keys.
    """
    norm = normalize_seed(seed)
    rng = rng_for(norm)
    pairs: list[tuple[str, str]] = []

    if host_key and case.get(host_key):
        pairs.append((str(case[host_key]), "host"))
    if user_key and case.get(user_key):
        pairs.append((str(case[user_key]), "user"))

    def _scan_blob(blob: str) -> None:
        pairs.extend(discover_text_surface(blob, allow_ip=allow_ip))
        for h in HOST_BANK:
            if h in blob:
                pairs.append((h, "host"))
        for u in USER_BANK:
            if u in blob:
                pairs.append((u, "user"))

    for key in text_keys or []:
        val = case.get(key)
        if isinstance(val, str):
            _scan_blob(val)
        elif isinstance(val, (dict, list)):
            _scan_blob(str(val))

    # Always scan nested tree command lines when present.
    tree = case.get("tree")
    if isinstance(tree, list):
        for node in tree:
            if isinstance(node, dict):
                for field in ("cmd", "name"):
                    if isinstance(node.get(field), str):
                        pairs.extend(
                            discover_text_surface(node[field], allow_ip=allow_ip)
                        )
                # Paths often embed the username.
                cmd = str(node.get("cmd") or "")
                for u in USER_BANK:
                    if u in cmd:
                        pairs.append((u, "user"))

    mapping = build_mapping(pairs, rng)
    out = apply_variant_tokens(case, mapping)
    if remap_tree_pids and isinstance(out.get("tree"), list):
        out["tree"] = remap_pids(out["tree"], rng)
    out["instance_seed"] = norm
    return out
