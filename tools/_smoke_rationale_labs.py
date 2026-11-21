"""Smoke: grade functions return answer_chips; expanded case counts look sane."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import automation_lab
import comms_lab
import edr_lab
import email_lab
import entra_lab
import intel_lab
import log_lab
import metrics_lab
import net_lab
import oversight_lab
import policy_lab
import sentinel_lab
import soar_career_lab
import tune_lab
import vuln_lab

FAILS = 0


def _ok(name: str, cond: bool, detail: str = "") -> None:
    global FAILS
    mark = "PASS" if cond else "FAIL"
    print(f"[{mark}] {name}" + (f" — {detail}" if detail else ""))
    if not cond:
        FAILS += 1


def _has_chips(result: dict) -> bool:
    chips = result.get("answer_chips") or []
    return bool(chips) and all("rationale" in c and "label" in c for c in chips)


def main() -> None:
    counts = {
        "email": len(email_lab.SAMPLES),
        "edr": len(edr_lab.CASES),
        "entra": len(entra_lab.CASES),
        "vuln": len(vuln_lab.CASES),
        "intel": len(intel_lab.CASES),
        "logs": len(log_lab.DRILLS),
        "net": len(net_lab.DRILLS),
        "sentinel": len(sentinel_lab.CASES),
        "comms": len(comms_lab.SCENARIOS),
        "tune": len(tune_lab.DRILLS),
        "oversight": len(oversight_lab.CASES),
        "soar": len(soar_career_lab.SCENARIOS),
        "policy": len(policy_lab.SCENARIOS),
        "automation": len(automation_lab.DRILLS),
        "metrics": len(metrics_lab.QUIZ),
    }
    for k, v in counts.items():
        print(f"  count {k}={v}")
        _ok(f"count_{k}", v >= 3, str(v))

    s = email_lab.get_sample("o365_cred_harvest")
    r = email_lab.grade_triage(
        "o365_cred_harvest", dict(s["checklist_answers"]), s["correct_disposition"]
    )
    _ok("email_grade", r.get("ok") and r.get("passed") and _has_chips(r), str(r.get("pct")))

    c = edr_lab.get_case("lsass_dump")
    r = edr_lab.grade_edr(
        "lsass_dump",
        dict(c["checklist_answers"]),
        c["correct_isolate"],
        c["correct_disposition"],
    )
    _ok("edr_grade", r.get("ok") and r.get("passed") and _has_chips(r))

    c = entra_lab.get_case("impossible_travel")
    r = entra_lab.grade_entra(
        "impossible_travel",
        dict(c["checklist_answers"]),
        c["correct_outcome"],
        c["correct_disposition"],
    )
    _ok("entra_grade", r.get("ok") and r.get("passed") and _has_chips(r))

    c = vuln_lab.get_case("exchange_proxy_style")
    r = vuln_lab.grade_vuln(
        "exchange_proxy_style",
        c["correct_priority"],
        c["correct_disposition"],
        dict(c["checklist_answers"]),
    )
    _ok("vuln_grade", r.get("ok") and r.get("passed") and _has_chips(r))

    c = intel_lab.get_case("ms_lookalike_login")
    r = intel_lab.grade_enrichment(
        "ms_lookalike_login",
        dict(c["checklist_answers"]),
        c["correct_disposition"],
        "micr0soft-secure.com malicious phish escalate lookup done",
    )
    _ok("intel_grade", r.get("ok") and r.get("passed") and _has_chips(r), str(r.get("pct")))

    d = log_lab.get_drill("linux_sudo_fail")
    r = log_lab.grade_drill(
        "linux_sudo_fail",
        d["correct_source"],
        d["correct_evidence"],
        dict(d["checklist_answers"]),
    )
    _ok("logs_grade", r.get("ok") and r.get("passed") and _has_chips(r))

    d = net_lab.get_drill("ssh_ingress_bruteforce")
    r = net_lab.grade_drill(
        "ssh_ingress_bruteforce",
        d["correct_signal"],
        d["correct_direction"],
        dict(d["checklist_answers"]),
    )
    _ok("net_grade", r.get("ok") and r.get("passed") and _has_chips(r))

    sc = sentinel_lab.CASES[0]
    r = sentinel_lab.grade_sentinel(
        sc["id"],
        dict(sc["checklist_answers"]),
        sc["correct_blade"],
        sc["correct_disposition"],
    )
    _ok("sentinel_grade", r.get("ok") and _has_chips(r))

    r = tune_lab.grade_tune("tn_proxy_cdn", "tune")
    _ok("tune_grade", r.get("ok") and r.get("passed") and _has_chips(r))

    r = oversight_lab.grade_oversight("ao_fp_patch", "override_fp", "sccm_chg")
    _ok("oversight_grade", r.get("ok") and r.get("passed") and _has_chips(r))

    r = soar_career_lab.grade_chain(
        "sc_ransom_isolate",
        enriched=True,
        decision="approve",
        reason="ransom isolate rename mass files",
        ticket_note="enriched approved isolate harbor",
    )
    _ok("soar_grade", r.get("ok") and r.get("passed") and _has_chips(r), str(r.get("pct")))

    r = policy_lab.grade_policy("pl_apply_harbor", {"choice": "manual_contain"})
    _ok("policy_grade", r.get("ok") and _has_chips(r))

    r = automation_lab.grade_automation("al_safe", {"choice": "a"})
    _ok("automation_grade", r.get("ok") and r.get("passed") and _has_chips(r))

    answers = {q["id"]: q["answer"] for q in metrics_lab.QUIZ}
    r = metrics_lab.grade_quiz(answers)
    _ok("metrics_grade", r.get("ok") and r.get("passed") and _has_chips(r))

    sc = next(s for s in comms_lab.SCENARIOS if s["id"] == "cm_spray_user")
    r = comms_lab.grade_draft("cm_spray_user", sc["good_shape"])
    _ok("comms_grade", r.get("ok") and _has_chips(r))

    if FAILS:
        print(f"\n{FAILS} check(s) failed.")
        raise SystemExit(1)
    print("\nAll smoke checks passed.")


if __name__ == "__main__":
    main()
