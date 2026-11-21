"""Rebuild Sec+ MCQ parallel-form pack with quality near-miss distractors.

Strategy:
1. Hand OVERRIDE for known worst offenders
2. STUB_EXPAND map for common short tech labels
3. Replace nonsense stubs (fonts/toner/memes) with family near-misses
4. Length-balance (shorten long corrects)
5. Ollama fallback only when still severe / too short

Writes tools/_mcq_parallel_pack.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPORT = ROOT / "tools" / "_mcq_export.json"
PACK = ROOT / "tools" / "_mcq_parallel_pack.json"
MODEL = "llama3.1:8b"
OLLAMA_URL = "http://localhost:11434/v1/chat/completions"

PCT_THRESH = 20.0
ABS_THRESH = 15

NONSENSE_RE = re.compile(
    r"\b(font|toner|meme|poster|printer|snmP|cage key|only domain|only cold|"
    r"only nids|only aup|only chg|only rpo|only ot|shame|nobody|nowhere|"
    r"none\b|perfect zt|required zt)\b",
    re.I,
)

# Common short tech stubs -> parallel near-miss phrases (wrong-on-purpose).
STUB_EXPAND: dict[str, str] = {
    "preventive": "Preventive block before the event succeeds",
    "detective": "Detective alert after the event is seen",
    "corrective": "Corrective cleanup after damage started",
    "directive": "Directive policy telling people what to do",
    "directive only": "Directive policy text with no technical enforce",
    "directive aup": "Directive AUP text without technical enforce",
    "compensating": "Compensating workaround with owner and end date",
    "deterrent": "Deterrent banner meant to scare attackers",
    "technical": "Technical control in software or config",
    "managerial": "Managerial governance artefact or risk acceptance",
    "managerial policy only": "Managerial policy document without tooling",
    "operational": "Operational process people run by checklist",
    "physical": "Physical control like locks or cameras",
    "physical only": "Physical door locks with no cyber controls",
    "physical badge": "Physical badge reader at the server room",
    "physical cage": "Physical cage lock around the rack",
    "confidentiality": "Confidentiality of sensitive data exposure",
    "integrity": "Integrity of records against unauthorized change",
    "availability": "Availability so systems stay usable under stress",
    "non-repudiation": "Non-repudiation so actions can be proven later",
    "mfa": "MFA challenge during interactive sign-in",
    "disable mfa": "Disable MFA to reduce user friction",
    "disabling mfa": "Disabling MFA across the tenant",
    "replace mfa": "Replace MFA with password-only logons",
    "vpn": "VPN tunnel assumed trusted after connect",
    "firewall": "Firewall allow rule treated as full trust",
    "edr": "EDR alert treated as automatic containment",
    "disable edr": "Disable EDR agents to quiet the noise",
    "siem": "SIEM dashboard watched without response actions",
    "disable siem": "Disable SIEM correlation to cut alert volume",
    "delete siem": "Delete SIEM rules after the first false positive",
    "open rdp": "Open inbound RDP from the internet",
    "opening rdp": "Opening inbound RDP for vendor convenience",
    "open 3389": "Open tcp/3389 from the public internet",
    "opening 3389": "Opening tcp/3389 without compensating controls",
    "open more ports": "Open more management ports to the internet",
    "open more rdp": "Open more RDP paths for faster support",
    "opening more rdp": "Opening more RDP listeners on servers",
    "it opens 3389": "It opens tcp/3389 as the main fix",
    "proof to open 3389": "Use the finding as proof to open 3389",
    "legacy auth": "Keep legacy authentication protocols enabled",
    "hashing": "Hashing a password so it cannot be reversed easily",
    "encryption": "Encryption of data so confidentiality holds in transit",
    "base64": "Base64 encoding mistaken for real encryption",
    "honeypot": "Honeypot decoy treated as primary prevention",
    "a honeypot": "A honeypot used instead of real monitoring",
    "honeypots": "Honeypots as the only detection strategy",
    "a honeypot success": "Calling a honeypot hit a full incident close",
    "rto": "RTO target alone without a tested restore path",
    "rpo": "RPO target alone without backup verification",
    "only rpo": "Only RPO numbers with no restore evidence",
    "set rto": "Set an RTO number without testing recovery",
    "delete logs": "Delete logs during response to reduce liability",
    "disable logging": "Disable logging to shrink storage costs",
    "no logging": "Turn off logging because alerts are noisy",
    "delete signinlogs": "Delete SigninLogs to hide the spray evidence",
    "turn off mailbox audit": "Turn off mailbox audit to quiet detections",
    "ignore": "Ignore the alert and wait for user complaints",
    "ignore after filing": "Ignore the risk after filing the paperwork",
    "escalate": "Escalate immediately with no triage notes",
    "isolate and preserve": "Isolate and preserve without notifying stakeholders",
    "chg tickets": "Change tickets alone without technical controls",
    "chg text": "Change-ticket wording without enforcement",
    "only chg": "Only a change ticket with no compensating control",
    "dns": "DNS change alone without identity or endpoint checks",
    "identification only": "Identification of the user without authentication",
    "faster spray": "Allow faster password spray by relaxing lockouts",
    "all phishing": "Treat every phishing report as confirmed compromise",
    "need for tickets": "Need for tickets without saying what control failed",
    "replace backups": "Replace backups with screenshots of dashboards",
    "replace ir": "Replace IR with a single status email thread",
    "disable accounting": "Disable accounting so failed logons are not tracked",
    "delete accounting": "Delete accounting records after the investigation",
    "aup reprint": "Reprint the AUP and call the risk closed",
    "only aup text": "Only AUP text with no technical enforcement",
    "only posters": "Only awareness posters in the break room",
    "only a poster": "Only a wall poster as the control",
    "only physical": "Only physical locks with no cyber detection",
    "only physical doors": "Only physical doors without identity controls",
    "only cold sites": "Only cold-site contracts with no restore tests",
    "only nids": "Only network IDS without endpoint visibility",
    "only for ot": "Only apply the control to OT networks",
    "only domain 1": "Only Domain 1 concepts apply to this scenario",
    "only domain 5": "Only Domain 5 governance with no ops action",
    "only memes": "Only share memes about the outage in chat",
    "only toner": "Only toner-level alerts from office printers",
    "only toner alerts": "Only toner alerts mistaken for security signal",
    "fonts": "Printer font inventory treated as a security control",
    "toner levels": "Toner levels used as the priority security metric",
    "printer snmp": "Printer SNMP traps as the main SOC signal",
    "none": "No control is needed for this scenario",
    "nobody": "Nobody needs to own the residual risk",
    "nowhere": "Nowhere to document the exception or owner",
    "required": "Treat the control as required with no risk review",
    "perfect zt": "Claim perfect Zero Trust so no monitoring is needed",
    "required zt": "Require Zero Trust branding without enforcement",
    "shame users": "Publicly shame users instead of fixing controls",
    "corrective password reset": "Corrective password reset after compromise",
    "authentication": "Authentication proving the claimed identity",
    "authorization": "Authorization deciding what the identity may do",
    "accounting": "Accounting that records actions for later review",
    "identification": "Identification naming the user without proof",
    "compensating vpn only": "Compensating VPN path treated as permanent fix",
    "compensating rdp open": "Compensating open RDP with no owner or end date",
    "skip control language": "Skip control language and only name the product",
    "only physical matters": "Claim only physical controls matter on the exam",
    "directive aup alone": "Directive AUP alone without technical enforce",
    "detective deception": "Detective deception such as a honeytoken alert",
    "proof of encryption": "Proof of encryption mistaken for full Zero Trust",
    "call every alert corrective": "Call every alert a corrective control",
    "physical cage lock": "Physical cage lock around the rack",
    "identical": "Claim tabletop and restore tests are identical",
    "neither useful": "Claim neither continuity exercise is useful",
    "smart": "Smart deletion of evidence to limit liability",
    "ui fashion": "Pick tools based on UI fashion instead of coverage",
    "poster only": "Awareness poster only with no mail controls",
    "shame cfo only": "Shame the CFO only with no process change",
    "open owa on 3389": "Open OWA on tcp/3389 for finance convenience",
    "only pizza": "Pizza budget meeting treated as risk governance",
    "dated restore test results vs rto/rpo": "Dated restore test results versus RTO/RPO",
}


# Pre-rotation order: correct stays at generator answer_idx.
OVERRIDE: dict[str, list[str]] = {
    "q_d3_02a": [
        "MFA prompts during interactive sign-in",
        "Implicit trust from network location alone",
        "Change tickets that authorize a temporary path",
        "EDR alerts that notify after host execution",
    ],
    "sp_d3_07_resilience_ha_p3": [
        "Printer font inventory as a security metric",
        "Attacks and failures both kill availability",
        "Physical locks alone without cyber recovery",
        "Change tickets alone without restore testing",
    ],
    "sp_d4_12_ir_comms_docs_p3": [
        "Smart deletion to shrink legal liability fast",
        "Destructive and likely obstructive to evidence",
        "Required cleanup once containment is declared",
        "Honeypot decoy used instead of log preservation",
    ],
    "sp_d4_08_tune_capabilities_p1": [
        "Delete SIEM rules after the first noisy alert",
        "Block source, tighten lockout, hunt successes",
        "Open tcp/3389 to make vendor support easier",
        "Disable MFA so users stop generating failures",
    ],
    "sp_d4_09_iam_ops_p3": [
        "No federation review because SSO feels faster",
        "Auth decisions outsourced to a weak IdP path",
        "Toner alerts treated as the identity priority",
        "Only RPO numbers with no identity hunt window",
    ],
    "q_d5_02a": [
        "Force re-evaluation before risk becomes permanent",
        "Open inbound RDP because the exception exists",
        "Disable SIEM alerts for the accepted exception",
        "Publicly shame users instead of reviewing risk",
    ],
    "q_d5_02b": [
        "Cross-functional risk decisions with authority",
        "Pizza budget approvals as the security forum",
        "Toner inventory reviews as governance theater",
        "Meme threads replacing risk decision owners",
    ],
    "q_d3_09d": [
        "Tabletop and restore tests are identical checks",
        "Tabletop stresses decisions; restore stresses recovery",
        "Neither exercise is useful for readiness proof",
        "Only OT environments need continuity testing",
    ],
    "q_d5_10d": [
        "BEC training, legacy auth off, DLP, callbacks",
        "Awareness poster only with no mail controls",
        "Shame the CFO only with no process change",
        "Open OWA on tcp/3389 for finance convenience",
    ],
    "sp_d4_13_sources_identity_p3": [
        "Pick log sources based on UI fashion trends",
        "Keep queries usable inside the incident window",
        "Disable MFA so identity queries stay quiet",
        "Open inbound RDP while identity hunts run",
    ],
    "q_d3_09b": [
        "A binder of plans that was never exercised",
        "Dated restore test results versus RTO/RPO",
        "More dashboards with no recovery evidence",
        "A verbal vendor promise of fast restore",
    ],
    "q_d5_03d": [
        "Ignore the entry after filing the paperwork",
        "Watch indicators that the risk is changing",
        "Delete the risk register to reduce findings",
        "Open more ports while the risk stays open",
    ],
    "sp_d2_06_ioc_identity_p1": [
        "Password spray across many accounts from one IP",
        "Credential stuffing against a single UPN only",
        "Pass-the-hash using a stolen NTLM credential",
        "Benign Defender noise with no auth failures",
    ],
    "sp_d3_05_data_states_p2": [
        "Data in transit between browser and Boundry UI",
        "Only data at rest on a stolen USB stick",
        "Physical cages as the TLS protection layer",
        "RTO number with no encryption requirement",
    ],
    "sp_d4_03_asset_management_p2": [
        "Lifecycle failure: asset with no owner or review",
        "Proof of perfect Zero Trust already in place",
        "Only Domain 1 vocabulary with no ops follow-up",
        "A honeypot used instead of inventory ownership",
    ],
    "sp_d5_03_risk_process_p2": [
        "Prioritize which risks to treat first",
        "Open inbound RDP as the default treatment",
        "Disable MFA to reduce risk scores quickly",
        "Delete logs so the risk register looks clean",
    ],
    "q_d1_03d": [
        "Confidentiality failure from cleartext exposure",
        "Only availability of MFA for the executive",
        "Directive scan ticket with no data impact",
        "SOAR playbook that never mentions the laptop",
    ],
    "q_d2_02c": [
        "Email and social engineering as the vector",
        "Only cage keys as the BEC delivery path",
        "Only NIDS signatures with no mail context",
        "RPO targets mistaken for phishing controls",
    ],
    "q_d3_06b": [
        "TLS or VPN protecting data in transit",
        "Only a badge reader as transit encryption",
        "Only a honeypot as the transit crypto tool",
        "Only AUP text as the encryption control",
    ],
    "q_d4_02a": [
        "Identity protocols and legacy auth paths",
        "Only printers as the hardening target",
        "Only cages as the legacy auth control",
        "Only RTO numbers as identity hardening",
    ],
    "q_d5_09a": [
        "Usually incomplete without technical controls",
        "Always enough when posters are printed",
        "Forbidden by every security framework",
        "Only required for OT network segments",
    ],
    "q_d5_11a": [
        "Theatre: lessons with no owners or dates",
        "Actionable program change with owners",
        "Automatic patch that closes every finding",
        "Open inbound RDP as the lessons follow-up",
    ],
}


def is_severe(choices: list[str], idx: int) -> bool:
    lens = [len(c) for c in choices]
    corr = lens[idx]
    max_other = max(lens[i] for i in range(4) if i != idx)
    if corr <= max_other:
        return False
    pct = (corr - max_other) / max_other * 100 if max_other else 100.0
    return pct >= PCT_THRESH or (corr - max_other) >= ABS_THRESH


def is_longest(choices: list[str], idx: int) -> bool:
    lens = [len(c) for c in choices]
    return lens[idx] > max(lens[i] for i in range(4) if i != idx)


def needs_rewrite(choices: list[str], idx: int) -> bool:
    if is_severe(choices, idx):
        return True
    others = [choices[i] for i in range(4) if i != idx]
    return sum(1 for c in others if len(c) <= 18 or len(c.split()) <= 2) >= 2


def strip_dashes(s: str) -> str:
    return s.replace("\u2014", ",").replace("\u2013", "-").replace("—", ",").replace("–", "-")


def shorten(text: str, target: int) -> str:
    """Shorten text without leaving dangling/truncated MCQ choice fragments."""
    from secplus_mcq_length_lint import is_shorten_unsafe

    original = " ".join(strip_dashes(text).split())
    t = original
    if len(t) <= target:
        return t
    for sep in [";", ":", ".", " / "]:
        if sep in t:
            left = t.split(sep)[0].strip()
            if 14 <= len(left) <= target + 10 and not is_shorten_unsafe(left):
                return left
    words = t.split()
    while len(" ".join(words)) > target and len(words) > 4:
        words.pop()
        candidate = " ".join(words)
        if not is_shorten_unsafe(candidate):
            t = candidate
            break
    else:
        t = " ".join(words)
    # Never ship a cut fragment; keep the original if shorten broke it.
    if is_shorten_unsafe(t):
        return original
    return t


def expand_one(stub: str, correct: str, target: int, salt: int = 0) -> str:
    """Expand or replace one distractor into a parallel near-miss."""
    s = " ".join(strip_dashes(stub).split())
    key = s.lower().rstrip(".")
    if key in STUB_EXPAND:
        return STUB_EXPAND[key]
    key2 = re.sub(r"^(only |a |the )", "", key)
    if key2 in STUB_EXPAND:
        return STUB_EXPAND[key2]
    # Already a usable multi-word near-miss: keep / gentle shorten
    if len(s.split()) >= 3 and len(s) >= 18:
        if len(s) > target + 16:
            return shorten(s, target + 6)
        return s
    if NONSENSE_RE.search(s) or len(s) <= 3:
        return "NEARMISS"
    if len(s) >= max(24, int(target * 0.7)):
        return shorten(s, target + 8) if len(s) > target + 16 else s
    # Preserve stub meaning with varied parallel templates (avoid shared clones)
    templates = [
        f"Treating {s} as enough protection here",
        f"Relying on {s} alone for this risk",
        f"Using {s} as the primary fix",
        f"Assuming {s} closes the gap",
        f"Choosing {s} instead of the right control",
        f"Making {s} the whole answer",
    ]
    return templates[int(salt) % len(templates)]


def family_alternates(correct: str, salt: int = 0) -> list[str]:
    """Near-miss pool inferred from correct wording, plus rotated fallback bank."""
    c = correct.lower()
    pools: list[list[str]] = []
    if any(w in c for w in ("prevent", "detect", "correct", "direct", "deterr", "compensat")):
        pools.append([
            "Preventive block before the event succeeds",
            "Detective alert after the event is seen",
            "Corrective cleanup after damage started",
            "Directive policy telling people what to do",
            "Deterrent banner meant to scare attackers",
            "Compensating workaround with owner and end date",
        ])
    if any(w in c for w in ("confidential", "integrity", "availab", "non-repud")):
        pools.append([
            "Confidentiality of sensitive data exposure",
            "Integrity of records against unauthorized change",
            "Availability so systems stay usable under stress",
            "Non-repudiation so actions can be proven later",
        ])
    if any(w in c for w in ("technical", "managerial", "operational", "physical")):
        pools.append([
            "Technical control in software or config",
            "Managerial governance artefact or risk acceptance",
            "Operational process people run by checklist",
            "Physical control like locks or cameras",
        ])
    fallback = [
        "Open inbound RDP from the internet",
        "Disable MFA to reduce user friction",
        "Delete logs during response to reduce liability",
        "Ignore the alert and wait for user complaints",
        "Disable SIEM correlation to cut alert volume",
        "Rely on awareness posters as the only control",
        "Treat Base64 encoding as real encryption",
        "Keep legacy authentication protocols enabled",
        "Set an RTO number without testing recovery",
        "Call every alert a corrective control",
        "Assume VPN connect equals full trust",
        "Skip control language and only name the tool",
        "Open more management ports for convenience",
        "Turn off endpoint telemetry to quiet noise",
        "Accept risk with no owner and no review date",
        "Replace IR with a single status email thread",
    ]
    # Rotate fallback so questions do not all clone the same first distractors
    rot = int(salt) % len(fallback)
    pools.append(fallback[rot:] + fallback[:rot])
    out: list[str] = []
    seen: set[str] = set()
    for pool in pools:
        for p in pool:
            pl = p.lower()
            if pl in seen or pl == c:
                continue
            seen.add(pl)
            out.append(p)
    return out


def balance(choices: list[str], idx: int, salt: int = 0) -> list[str]:
    out = [strip_dashes(c) for c in choices]
    correct = out[idx]
    # Expand short correct stubs too so parallel form is not "short correct + long distractors"
    if len(correct) <= 18 or len(correct.split()) <= 2:
        key = correct.lower().rstrip(".")
        if key in STUB_EXPAND:
            correct = STUB_EXPAND[key]
        else:
            # Never invent NEARMISS for the correct concept; clarify in place.
            correct = f"{correct}: best match for this stem"
    if correct == "NEARMISS" or correct.startswith("NEARMISS"):
        correct = out[idx]  # restore original
        if len(correct) <= 24:
            correct = f"{correct}: best match for this stem"
    target = min(52, max(34, len(shorten(correct, 46))))
    out[idx] = shorten(correct, target)
    alts = family_alternates(out[idx], salt=salt)
    alt_i = 0
    used = {out[idx].lower()}
    for i in range(4):
        if i == idx:
            continue
        cur = out[i]
        if (
            NONSENSE_RE.search(cur)
            or len(cur) <= 18
            or len(cur.split()) <= 2
            or len(cur) < int(target * 0.7)
            or cur.lower() in used
        ):
            expanded = expand_one(cur, out[idx], target, salt=salt + i)
            if (
                NONSENSE_RE.search(cur)
                or expanded == "NEARMISS"
                or "as the main security control" in expanded
                or "as the primary answer here" in expanded
            ):
                while alt_i < len(alts) and alts[alt_i].lower() in used:
                    alt_i += 1
                if alt_i < len(alts):
                    expanded = alts[alt_i]
                    alt_i += 1
                elif expanded == "NEARMISS":
                    expanded = f"Wrong near-miss: {cur}"
            out[i] = expanded
        elif len(cur) > target + 18:
            out[i] = shorten(cur, target + 6)
        used.add(out[i].lower())
    for i in range(4):
        if i == idx:
            continue
        if out[i].lower() == out[idx].lower() or out.count(out[i]) > 1:
            while alt_i < len(alts) and alts[alt_i].lower() in {x.lower() for x in out}:
                alt_i += 1
            if alt_i < len(alts):
                out[i] = alts[alt_i]
                alt_i += 1
    if is_severe(out, idx):
        max_other = max(len(out[i]) for i in range(4) if i != idx)
        out[idx] = shorten(out[idx], max(22, max_other))
    # Final: expand any remaining short distractors / NEARMISS markers
    for i in range(4):
        if i == idx:
            continue
        if (
            out[i] == "NEARMISS"
            or out[i].startswith("Wrong near-miss")
            or len(out[i]) < 22
            or len(out[i].split()) <= 2
        ):
            while alt_i < len(alts) and alts[alt_i].lower() in {x.lower() for x in out}:
                alt_i += 1
            if alt_i < len(alts):
                out[i] = alts[alt_i]
                alt_i += 1
            else:
                expanded = expand_one(out[i], out[idx], len(out[idx]), salt=salt + i + 7)
                if expanded != "NEARMISS" and expanded.lower() not in {x.lower() for x in out}:
                    out[i] = expanded
                else:
                    out[i] = f"Unrelated control choice {i + 1} for this stem"
    return out

def quality_ok(choices: list[str], idx: int) -> bool:
    if len(choices) != 4 or any(len(c.strip()) < 8 for c in choices):
        return False
    if len({c.lower() for c in choices}) < 4:
        return False
    if is_severe(choices, idx):
        return False
    if any(NONSENSE_RE.search(choices[i]) for i in range(4) if i != idx):
        # nonsense left in distractor = not ok
        if any(len(choices[i]) <= 20 for i in range(4) if i != idx):
            return False
    generics = ("as the primary answer here", "as the main security control", "as the primary control here")
    if sum(1 for c in choices if any(g in c for g in generics)) >= 2:
        return False
    lens = [len(c) for c in choices]
    return max(lens) - min(lens) <= 36


def ollama_rewrite(item: dict) -> list[str] | None:
    idx = item["answer_idx"]
    labeled = []
    for i, c in enumerate(item["choices"]):
        role = "CORRECT" if i == idx else "WRONG"
        labeled.append(f"[{i}] {role}: {c}")
    prompt = f"""EXAMPLE:
STEM: Zero Trust rejects:
[0] WRONG: MFA
[1] CORRECT: Implicit trust from network location alone
[2] WRONG: Tickets
[3] WRONG: EDR
OUTPUT: {{"choices":["MFA prompts during interactive sign-in","Implicit trust from network location alone","Change tickets that authorize a temporary path","EDR alerts that notify after host execution"],"answer_idx":1}}

Rewrite options. answer_idx={idx}. Keep CORRECT concept (shorten OK).
Replace WRONG short/nonsense stubs with plausible near-miss tech phrases of similar length.
Distractors must stay WRONG and must NOT paraphrase the correct answer.
Same grammar pattern. No em dashes. JSON only.

STEM: {item['stem']}
{chr(10).join(labeled)}
"""
    for attempt in range(4):
        try:
            body = json.dumps({
                "model": MODEL,
                "temperature": 0.2 + 0.1 * attempt,
                "messages": [
                    {"role": "system", "content": "Rewrite MCQ options. JSON only."},
                    {"role": "user", "content": prompt},
                ],
            }).encode()
            req = urllib.request.Request(
                OLLAMA_URL, data=body, headers={"Content-Type": "application/json"}, method="POST"
            )
            with urllib.request.urlopen(req, timeout=180) as resp:
                raw = json.loads(resp.read().decode())["choices"][0]["message"]["content"]
            raw = raw.strip()
            m = re.search(r"\{[\s\S]*\}", raw)
            if not m:
                continue
            parsed = json.loads(m.group(0))
            new_c = [strip_dashes(str(x).strip()) for x in parsed["choices"]]
            if quality_ok(new_c, idx) or (len(new_c) == 4 and not is_severe(new_c, idx)):
                return new_c
        except Exception as exc:  # noqa: BLE001
            print(f"  ollama: {exc}")
            time.sleep(0.3)
    return None


def rewrite_item(item: dict, use_ollama: bool) -> list[str] | None:
    idx = item["answer_idx"]
    iid = item["id"]
    salt = sum(ord(ch) for ch in iid) % 97
    if iid in OVERRIDE:
        ch = [strip_dashes(c) for c in OVERRIDE[iid]]
        if not is_severe(ch, idx):
            return ch
    ruled = balance(item["choices"], idx, salt=salt)
    if quality_ok(ruled, idx):
        return ruled
    if not is_severe(ruled, idx) and len({c.lower() for c in ruled}) == 4:
        # Accept if only mild generic issues
        generics = sum(
            1
            for c in ruled
            if "as the primary answer here" in c or "as the main security control" in c
        )
        if generics <= 1:
            return ruled
    if use_ollama:
        return ollama_rewrite(item) or ruled
    return ruled


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--ids", default="")
    ap.add_argument("--no-ollama", action="store_true")
    ap.add_argument("--ollama-bad-only", action="store_true",
                    help="Rules for all; Ollama only when quality_ok fails")
    args = ap.parse_args()

    items = json.loads(EXPORT.read_text(encoding="utf-8"))
    id_filter = {x.strip() for x in args.ids.split(",") if x.strip()} or None
    pack: dict = {}

    todo = []
    for item in items:
        if id_filter and item["id"] not in id_filter:
            continue
        # Rewrite everything that needs it OR all if filtered
        if id_filter or needs_rewrite(item["choices"], item["answer_idx"]) or item["id"] in OVERRIDE:
            todo.append(item)
        else:
            # Still include non-severe items unchanged so pack can be complete optional
            pass
    if args.limit:
        todo = todo[: args.limit]

    print(f"todo={len(todo)}")
    ok = fail = ollama_n = 0
    for n, item in enumerate(todo, 1):
        iid = item["id"]
        use_o = not args.no_ollama
        if args.ollama_bad_only:
            ruled = balance(
                item["choices"],
                item["answer_idx"],
                salt=sum(ord(ch) for ch in item["id"]) % 97,
            )
            if quality_ok(ruled, item["answer_idx"]) or (
                not is_severe(ruled, item["answer_idx"])
                and sum(1 for c in ruled if "as the primary" in c or "as the main security" in c) <= 1
            ):
                new_c = ruled if iid not in OVERRIDE else [strip_dashes(c) for c in OVERRIDE[iid]]
                if iid in OVERRIDE:
                    new_c = [strip_dashes(c) for c in OVERRIDE[iid]]
                use_o = False
            else:
                use_o = True
                ollama_n += 1
                print(f"[{n}/{len(todo)}] {iid} (ollama)", flush=True)
                new_c = rewrite_item(item, True)
                pack[iid] = _entry(new_c, item)
                if new_c:
                    ok += 1
                else:
                    fail += 1
                if n % 5 == 0:
                    _save(pack)
                continue
        else:
            if n % 25 == 1 or use_o:
                print(f"[{n}/{len(todo)}] {iid}", flush=True)
        new_c = rewrite_item(item, use_o and not args.ollama_bad_only)
        if not new_c:
            fail += 1
            continue
        # If ollama_bad_only path already handled
        if args.ollama_bad_only and use_o:
            continue
        # Second chance with ollama if still severe
        if is_severe(new_c, item["answer_idx"]) and not args.no_ollama:
            print(f"  severe -> ollama {iid}", flush=True)
            alt = ollama_rewrite(item)
            if alt:
                new_c = alt
                ollama_n += 1
        pack[iid] = _entry(new_c, item)
        ok += 1
        if n % 20 == 0:
            _save(pack)

    _save(pack)
    sev = sum(1 for v in pack.values() if v["severe"])
    lng = sum(1 for v in pack.values() if v["longest"])
    gen = sum(
        1
        for v in pack.values()
        if any(
            "as the primary" in c or "as the main security" in c or c.startswith("NEARMISS") or c.startswith("Wrong near-miss")
            for c in v["choices"]
        )
    )
    print(
        f"done ok={ok} fail={fail} size={len(pack)} severe={sev} longest={lng} "
        f"genericish={gen} ollama_calls~={ollama_n}"
    )


def _entry(new_c: list[str], item: dict) -> dict:
    idx = item["answer_idx"]
    return {
        "choices": new_c,
        "answer_idx": idx,
        "lens": [len(c) for c in new_c],
        "severe": is_severe(new_c, idx),
        "longest": is_longest(new_c, idx),
    }


def _save(pack: dict) -> None:
    PACK.write_text(json.dumps(pack, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
