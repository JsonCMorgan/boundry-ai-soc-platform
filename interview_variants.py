"""
Interview Gym variants — curated packs + Ollama-generated angles.

Core scenarios in interview_gym.py stay the unlock spine.
Variants let Jason practice the same skill from new angles:
  - curated: hand-authored remixes (stable, offline)
  - ai: Ollama JSON (fallback to next unused curated pack if AI fails)
"""

from __future__ import annotations

import copy
import json
import re
import uuid
from typing import Any, Callable

import interview_gym

STEP_IDS = [s["id"] for s in interview_gym.STEPS]

# ── Curated overlays (2 per core scenario) ───────────────────────────────────
# Each overlay: new label/prompt + optional text replacements applied to a
# deep copy of the parent (guided teach/choices/example + model).

CURATED_PACKS: dict[str, list[dict[str, Any]]] = {
    "phishing_bec": [
        {
            "key": "payroll_redirect",
            "label": "HR payroll redirect",
            "prompt": (
                "An HR coordinator reports an email that looks like it is from the CHRO "
                "asking them to update a vendor employee's direct-deposit account today. "
                "Walk me through your investigation."
            ),
            "replacements": {
                "finance employee": "HR coordinator",
                "CFO": "CHRO",
                "wire $50,000": "payroll direct-deposit change",
                "wire process": "payroll change process",
                "wire-approval": "payroll-approval",
                "wire transfer": "payroll diversion",
                "Finance user": "HR user",
            },
        },
        {
            "key": "vendor_w9",
            "label": "Vendor W-9 / banking update",
            "prompt": (
                "Accounts payable forwards a 'vendor banking update' email with a PDF. "
                "The display name matches a real supplier, but the Reply-To is a free mail domain. "
                "Walk me through your investigation."
            ),
            "replacements": {
                "CFO": "vendor contact",
                "wire $50,000": "updated banking details for an invoice",
                "finance employee": "AP clerk",
                "Finance user": "AP user",
                "wire process": "vendor-change process",
            },
        },
    ],
    "impossible_travel": [
        {
            "key": "contractor_singapore",
            "label": "Contractor Singapore login",
            "prompt": (
                "Your SIEM fires: contractor account c.lee signed in from Singapore at 02:10 local. "
                "c.lee is a US-based contractor who usually works from Denver VPN. What do you do?"
            ),
            "replacements": {
                "jsmith": "c.lee",
                "Romania": "Singapore",
                "marketing coordinator": "US contractor",
                "Chicago": "Denver",
                "marketing": "contractor",
            },
        },
        {
            "key": "exec_assist_brazil",
            "label": "Exec assistant Brazil login",
            "prompt": (
                "Alert: exec assistant a.nguyen has a successful cloud login from Brazil, "
                "ten minutes after a successful login from Toronto HQ. MFA shows push approved. "
                "What do you do?"
            ),
            "replacements": {
                "jsmith": "a.nguyen",
                "Romania": "Brazil",
                "marketing coordinator in Chicago": "exec assistant in Toronto",
                "Chicago": "Toronto",
            },
        },
    ],
    "edr_powershell": [
        {
            "key": "finance_macro",
            "label": "Finance laptop macro chain",
            "prompt": (
                "EDR flags a finance laptop: excel.exe launched powershell.exe with -enc after "
                "opening Remit_Advice.xlsx from Downloads. Walk me through your next steps."
            ),
            "replacements": {
                "sales laptop": "finance laptop",
                "Invoice.xlsm": "Remit_Advice.xlsx",
                "Sales laptop": "Finance laptop",
            },
        },
        {
            "key": "helpdesk_tooling",
            "label": "Helpdesk remote tool FP angle",
            "prompt": (
                "EDR alerts on encoded PowerShell on a helpdesk jump host used for remote support. "
                "There is an open change ticket for a scripted cleanup. Walk me through triage."
            ),
            "replacements": {
                "sales laptop": "helpdesk jump host",
                "Sales laptop": "Helpdesk jump host",
                "unusual": "possibly expected for support tooling",
            },
        },
    ],
    "lateral_rdp": [
        {
            "key": "intern_to_fileservers",
            "label": "Intern workstation to file shares",
            "prompt": (
                "Alert: unusual RDP from an intern workstation to two file servers after hours, "
                "using a service account. Walk me through your investigation."
            ),
            "replacements": {
                "contractor workstation": "intern workstation",
                "three internal servers": "two file servers",
                "contractor": "intern",
            },
        },
        {
            "key": "vpn_to_dc",
            "label": "VPN user to domain controller",
            "prompt": (
                "SIEM shows RDP from a VPN-connected laptop to a domain controller. "
                "The user is in marketing and has no admin role on record. What do you do?"
            ),
            "replacements": {
                "contractor workstation": "VPN laptop",
                "three internal servers": "a domain controller",
                "contractor": "marketing user",
            },
        },
    ],
    "exfil_dlp": [
        {
            "key": "slack_export",
            "label": "Slack file export to personal",
            "prompt": (
                "DLP alerts that a departing engineer uploaded a zip of 'customer_exports' "
                "to a personal cloud drive via browser. Walk me through your response."
            ),
            "replacements": {
                "external forward": "personal cloud upload",
                "inbox rule": "browser upload",
                "mail": "file transfer",
            },
        },
        {
            "key": "usb_staging",
            "label": "USB staging on laptop",
            "prompt": (
                "Endpoint DLP flags large copies of finance CSVs to a USB device on a "
                "contractor laptop that is scheduled to leave Friday. What do you do?"
            ),
            "replacements": {
                "external forward": "USB copy",
                "inbox rule": "removable media write",
                "email": "USB transfer",
            },
        },
    ],
    "escalate_vs_close": [
        {
            "key": "noisy_scanner",
            "label": "Authorized vuln scanner noise",
            "prompt": (
                "You have 40 'port sweep' alerts from one internal IP. Change ticket CHG-884 "
                "shows a weekly Nessus window that matches. How do you decide escalate vs close?"
            ),
            "replacements": {
                "queue": "port-sweep queue",
                "alert": "scanner alert",
            },
        },
        {
            "key": "vip_mailbox",
            "label": "VIP mailbox rule ambiguity",
            "prompt": (
                "A VIP mailbox has a new forwarding rule to an external Gmail. "
                "The VIP says they set it for vacation. How do you decide escalate vs close?"
            ),
            "replacements": {
                "escalate-vs-close": "forwarding-rule escalate-vs-close",
            },
        },
    ],
    "password_spray": [
        {
            "key": "legacy_auth_burst",
            "label": "Legacy auth spray",
            "prompt": (
                "Identity logs show many failures across 80 accounts from one IP using legacy auth, "
                "then one success on a service account without MFA. Walk me through it."
            ),
            "replacements": {
                "password spray": "legacy-auth password spray",
                "spray": "legacy spray",
            },
        },
        {
            "key": "m365_federated",
            "label": "M365 federated tenant spray",
            "prompt": (
                "Microsoft 365 reports a password spray against your federated domain. "
                "No successes yet. What do you validate, correlate, and decide?"
            ),
            "replacements": {
                "SIEM": "M365 identity protection / SIEM",
            },
        },
    ],
    "powershell_fp": [
        {
            "key": "sccm_script",
            "label": "SCCM maintenance script",
            "prompt": (
                "EDR flags encoded PowerShell on 12 laptops at once. SCCM shows a signed "
                "maintenance package deploying at that minute. Walk me through FP vs true positive."
            ),
            "replacements": {
                "false positive": "SCCM-related false positive",
                "admin tool": "SCCM package",
            },
        },
        {
            "key": "security_tool_update",
            "label": "Security agent self-update",
            "prompt": (
                "A burst of PowerShell alerts matches your EDR agent's known update publisher "
                "and hash allow-list, but one host also shows a weird child process. What do you do?"
            ),
            "replacements": {
                "false positive": "agent-update false positive",
            },
        },
    ],
}


def _apply_replacements(text: str, replacements: dict[str, str]) -> str:
    """Apply longest-first string replacements."""
    out = text
    for old in sorted(replacements.keys(), key=len, reverse=True):
        out = out.replace(old, replacements[old])
    return out


def _remix_obj(obj: Any, replacements: dict[str, str]) -> Any:
    """Deep-copy structure with string replacements."""
    if isinstance(obj, str):
        return _apply_replacements(obj, replacements)
    if isinstance(obj, list):
        return [_remix_obj(x, replacements) for x in obj]
    if isinstance(obj, dict):
        return {k: _remix_obj(v, replacements) for k, v in obj.items()}
    return obj


def materialize_curated(parent_id: str, pack: dict[str, Any]) -> dict[str, Any] | None:
    """Build a full scenario dict from a curated pack overlay."""
    base = interview_gym.get_scenario(parent_id)
    if not base:
        return None
    reps = dict(pack.get("replacements") or {})
    scenario = _remix_obj(copy.deepcopy(base), reps)
    scenario["id"] = parent_id  # parent skill id for unlocks
    scenario["parent_id"] = parent_id
    scenario["variant_key"] = str(pack.get("key") or "curated")
    scenario["variant_label"] = str(pack.get("label") or "Curated angle")
    scenario["variant_source"] = "curated"
    scenario["prompt"] = str(pack.get("prompt") or scenario.get("prompt") or "")
    scenario["title"] = f"{base.get('title')} · {scenario['variant_label']}"
    return scenario


def list_curated_packs(parent_id: str) -> list[dict[str, str]]:
    """Public list of curated angles for a parent skill."""
    out = []
    for p in CURATED_PACKS.get(parent_id) or []:
        out.append({
            "key": str(p["key"]),
            "label": str(p["label"]),
            "source": "curated",
        })
    return out


def pick_curated_pack(parent_id: str, avoid_keys: set[str] | None = None) -> dict[str, Any] | None:
    """Next curated pack, skipping keys already used when possible."""
    packs = CURATED_PACKS.get(parent_id) or []
    if not packs:
        return None
    avoid = avoid_keys or set()
    for p in packs:
        if p["key"] not in avoid:
            return p
    return packs[0]


def _validate_scenario_shape(data: dict[str, Any], parent: dict[str, Any]) -> dict[str, Any] | None:
    """Return a cleaned scenario or None if AI JSON is unusable."""
    prompt = str(data.get("prompt") or "").strip()
    if len(prompt) < 40:
        return None
    guided_in = data.get("guided") or {}
    model_in = data.get("model") or {}
    guided: dict[str, Any] = {}
    model: dict[str, str] = {}
    for sid in STEP_IDS:
        g = guided_in.get(sid) if isinstance(guided_in, dict) else None
        if not isinstance(g, dict):
            return None
        choices = g.get("choices")
        if not isinstance(choices, list) or len(choices) != 3:
            return None
        choices = [str(c).strip()[:240] for c in choices]
        if any(len(c) < 8 for c in choices):
            return None
        try:
            answer_idx = int(g.get("answer_idx"))
        except (TypeError, ValueError):
            return None
        if answer_idx not in (0, 1, 2):
            return None
        teach = str(g.get("teach") or "").strip()[:500]
        example = str(g.get("example") or "").strip()[:500]
        if len(teach) < 20 or len(example) < 20:
            return None
        guided[sid] = {
            "teach": teach,
            "choices": choices,
            "answer_idx": answer_idx,
            "example": example,
        }
        model[sid] = str(model_in.get(sid) or example)[:400]
    label = str(data.get("variant_label") or data.get("label") or "AI angle").strip()[:80]
    return {
        "id": parent["id"],
        "parent_id": parent["id"],
        "order": parent.get("order"),
        "title": f"{parent.get('title')} · {label}",
        "tag": parent.get("tag"),
        "difficulty": parent.get("difficulty"),
        "prompt": prompt[:800],
        "why_hm": str(data.get("why_hm") or parent.get("why_hm") or "")[:400],
        "guided": guided,
        "model": model,
        "variant_key": f"ai_{uuid.uuid4().hex[:10]}",
        "variant_label": label,
        "variant_source": "ai",
    }


def build_ai_variant_prompt(parent: dict[str, Any]) -> str:
    """Prompt for Ollama to invent a new angle of the same interview skill."""
    return "\n".join([
        "You create ORIGINAL SOC Tier-1 interview scenario variants for training.",
        "Keep the SAME skill and investigation skeleton. Change names, orgs, IOCs, and angles.",
        "Define nothing illegal. No real malware code. No CompTIA exam dumps.",
        "Return ONLY JSON with keys: variant_label, prompt, why_hm, guided, model.",
        "guided must have keys: validate, context, analyze, correlate, decide, change_mind.",
        "Each guided step: teach (string), choices (exactly 3 strings), answer_idx (0-2), example (string).",
        "Mix answer_idx across steps (not always 0). Wrong choices must be plausible near-misses.",
        "model: same six keys with short ideal answers.",
        "",
        f"Parent skill id: {parent.get('id')}",
        f"Parent title: {parent.get('title')}",
        f"Parent tag: {parent.get('tag')}",
        f"Parent prompt (do not copy; invent a new angle): {parent.get('prompt')}",
        f"Why HMs ask: {parent.get('why_hm')}",
    ])


def generate_ai_variant(
    parent_id: str,
    call_ollama: Callable[..., str],
) -> dict[str, Any] | None:
    """Ask Ollama for a variant; return validated scenario or None."""
    parent = interview_gym.get_scenario(parent_id)
    if not parent:
        return None
    prompt = build_ai_variant_prompt(parent)
    try:
        raw = call_ollama(
            prompt,
            max_tokens=1800,
            temperature=0.7,
            timeout=120,
            system=(
                "You are Boundry Interview Gym content author. JSON only. "
                "Original scenarios. Plausible Tier-1 near-miss wrong answers."
            ),
        )
    except Exception:
        return None
    cleaned = re.sub(r"```[a-z]*\n?", "", raw or "").replace("```", "").strip()
    try:
        data = json.loads(cleaned)
    except Exception:
        m = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if not m:
            return None
        try:
            data = json.loads(m.group())
        except Exception:
            return None
    if not isinstance(data, dict):
        return None
    return _validate_scenario_shape(data, parent)


def new_instance_id() -> str:
    """UUID for a stored practice instance."""
    return uuid.uuid4().hex
