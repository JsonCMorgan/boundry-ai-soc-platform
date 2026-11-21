"""Smoke + wiring tests for Security+ SY0-701 Phase 1 micro-lesson tutor."""
from pathlib import Path
import sys

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import secplus_learn
import career_lab


def test_secplus_module_spine_and_mixed_grade():
    """50–65 lessons, D1→D5 order, 27 objectives, distinct banks, mixed answer_idx."""
    ids = secplus_learn.lesson_ids()
    assert 50 <= len(ids) <= 65, len(ids)
    assert [d["weight"] for d in secplus_learn.DOMAINS] == [16, 24, 19, 27, 14]
    assert secplus_learn.domain_ids() == [
        "d1_concepts",
        "d2_threats",
        "d3_architecture",
        "d4_operations",
        "d5_oversight",
    ]

    by_dom = {}
    for L in secplus_learn.LESSONS:
        by_dom[L["domain_id"]] = by_dom.get(L["domain_id"], 0) + 1
    assert by_dom["d1_concepts"] == 6
    assert by_dom["d2_threats"] == 14
    assert by_dom["d3_architecture"] == 9
    assert by_dom["d4_operations"] == 20
    assert by_dom["d5_oversight"] == 11

    # Exam order: domains never go backwards along the spine.
    last_dom = 0
    for L in secplus_learn.LESSONS:
        assert L["domain_order"] >= last_dom
        last_dom = L["domain_order"]
        # Option 1 depth bar: ~15–20 min Show-me (hyphen range, not em dash).
        assert 12 <= L["minutes"] <= 20
        assert L.get("objective_ref")
        assert L.get("key_terms")
        assert 2 <= len(L["sections"]) <= 3
        assert L.get("objective_exam") == "SY0-801"

    objs = secplus_learn.must_cover_objectives()
    # SY0-801 matrix has 27 objectives; spine should cover all after retag + new 2.1/2.6.
    assert len(objs) == 27
    assert objs[0] == "1.1" and objs[-1] == "5.6"
    assert "2.1" in objs and "2.6" in objs

    pbq_n = len(secplus_learn.PBQS)
    assert 12 <= pbq_n <= 15, pbq_n

    quiz_ids = []
    quiz_texts = []
    all_idx = []
    for lid in ids:
        bank = secplus_learn.get_quiz(lid)
        assert 3 <= len(bank) <= 5, lid
        assert secplus_learn.get_practice(lid), lid
        idxs = secplus_learn.quiz_answer_indices(lid)
        assert idxs, lid
        all_idx.extend(idxs)
        for q in bank:
            quiz_ids.append(q["id"])
            quiz_texts.append(q["q"])
            assert 0 <= q["answer_idx"] <= 3

    assert len(quiz_ids) == len(set(quiz_ids))
    assert len(quiz_texts) == len(set(quiz_texts))
    assert len(set(all_idx)) >= 3

    sample = ids[0]
    answers = {
        q["id"]: secplus_learn.CHOICE_LETTERS[q["answer_idx"]]
        for q in secplus_learn.get_quiz(sample)
    }
    good = secplus_learn.grade_quiz(sample, answers)
    assert good["ok"] and good["passed"] and good["pct"] == 100
    bad = secplus_learn.grade_quiz(sample, {q["id"]: "Z" for q in secplus_learn.get_quiz(sample)})
    assert bad["ok"] and not bad["passed"] and bad["pct"] == 0


def test_continue_advances_only_after_prove_pass():
    """Hybrid soft unlock: Continue pointer moves only after prove pass."""
    ids = secplus_learn.lesson_ids()
    first = ids[0]
    second = ids[1]
    assert secplus_learn.next_incomplete_lesson(set())["id"] == first
    assert secplus_learn.next_incomplete_lesson({first})["id"] == second
    assert secplus_learn.next_incomplete_lesson(set(ids)) is None


def test_secplus_pbq_and_practice_grade():
    """Help-me + a Watch-me PBQ still grade locally."""
    lid = "sp_d1_01_control_functions"
    pitems = secplus_learn.get_practice(lid)
    assert pitems
    pid = pitems[0]["id"]
    letter = secplus_learn.CHOICE_LETTERS[pitems[0]["answer_idx"]]
    p = secplus_learn.check_practice_answer(lid, pid, letter)
    assert p["ok"] and p["correct"]
    p_bad = secplus_learn.check_practice_answer(lid, pid, "Z")
    assert p_bad["ok"] and not p_bad["correct"]

    # IR order PBQ on D4
    ir_id = "sp_d4_11_ir_phases"
    assert secplus_learn.get_pbq(ir_id)
    order = secplus_learn.check_pbq_answer(
        ir_id,
        {"order": ["analyze", "contain", "eradicate", "recover", "lessons"]},
    )
    assert order["ok"] and order["correct"]
    order_bad = secplus_learn.check_pbq_answer(
        ir_id,
        {"order": ["recover", "analyze", "contain", "eradicate", "lessons"]},
    )
    assert order_bad["ok"] and not order_bad["correct"]


def test_prove_it_gate_includes_secplus():
    gates = career_lab.build_prove_it_gates(
        spl_lessons_done=0,
        spl_lessons_total=6,
        spl_quiz_passed=False,
        secplus_lessons_passed=10,
        secplus_lessons_total=54,
        secplus_domains_passed=0,
        secplus_domains_total=5,
    )
    sec = next(g for g in gates if g["id"] == "secplus")
    assert sec["href"] == "/career/secplus"
    assert "10/54" in sec["detail"]
    assert sec["pct"] == 19
    assert not sec["done"]

    done = career_lab.build_prove_it_gates(
        spl_lessons_done=0,
        spl_lessons_total=6,
        spl_quiz_passed=False,
        secplus_lessons_passed=54,
        secplus_lessons_total=54,
        secplus_domains_passed=5,
        secplus_domains_total=5,
    )
    sec2 = next(g for g in done if g["id"] == "secplus")
    assert sec2["done"] and sec2["pct"] == 100


def test_saturday_drill_keeps_portfolio_and_has_secplus():
    sat = next(d for d in career_lab.WEEKLY_DRILL_PLAN if d["weekday"] == 5)
    hrefs = [c["href"] for c in sat["ctas"]]
    assert "/career/portfolio" in hrefs
    assert any(h.startswith("/career/secplus") for h in hrefs)
    pointed = career_lab.point_saturday_secplus_cta(sat, "sp_d2_06_ioc_identity")
    sec_cta = next(c for c in pointed["ctas"] if c["href"].startswith("/career/secplus"))
    assert sec_cta["href"] == "/career/secplus/lesson/sp_d2_06_ioc_identity"
    mon = next(d for d in career_lab.WEEKLY_DRILL_PLAN if d["weekday"] == 0)
    thu = next(d for d in career_lab.WEEKLY_DRILL_PLAN if d["weekday"] == 3)
    assert mon["ctas"][0]["href"] == "/career/spl"
    assert any(c["href"] == "/career/kql" for c in thu["ctas"])


def _analyst_session(client):
    import app as app_module

    app_module.db_run(
        f"UPDATE users SET role = {app_module.PH} WHERE username = {app_module.PH}",
        ("analyst", "admin"),
    )
    row = app_module.db_fetchone(
        f"SELECT id FROM users WHERE username = {app_module.PH}",
        ("admin",),
    )
    with client.session_transaction() as sess:
        sess["username"] = "admin"
        sess["role"] = "analyst"
        sess["user_id"] = row["id"]
        sess["analyst_mode"] = "study"
    return row["id"]


def test_quiz_page_when_no_prove_bank(client):
    """Sessions without exam Prove MCQs get an explain page, not Flask 404."""
    _analyst_session(client)
    # Only the private Messer track has sessions without a Prove bank.
    if secplus_learn._messer_track() is None:
        return
    for lid in secplus_learn.lesson_ids():
        if secplus_learn.lesson_has_quiz(lid):
            continue
        resp = client.get(f"/career/secplus/quiz/{lid}")
        assert resp.status_code == 200
        assert b"Prove-it is not ready" in resp.data
        return


def test_secplus_routes_and_career_wiring(client):
    _analyst_session(client)

    hub = client.get("/career/secplus")
    assert hub.status_code == 200
    assert b"Security+" in hub.data
    assert b"General Security Concepts" in hub.data
    assert b"27%" in hub.data
    assert b"Continue" in hub.data
    assert b"Term bank" in hub.data or b"term bank" in hub.data.lower()

    first = secplus_learn.lesson_ids()[0]
    # Soft browse a later lesson without hard 403
    later = [L for L in secplus_learn.LESSONS if L["domain_order"] == 4][0]
    late = client.get(f"/career/secplus/lesson/{later['id']}")
    assert late.status_code == 200
    assert b"Show me" in late.data

    lesson = client.get(f"/career/secplus/lesson/{first}")
    assert lesson.status_code == 200
    assert b"Show me" in lesson.data

    practice = client.get(f"/career/secplus/practice/{first}")
    assert practice.status_code == 200
    assert b"Help me" in practice.data

    quiz = client.get(f"/career/secplus/quiz/{first}")
    assert quiz.status_code == 200
    assert b"prove it" in quiz.data.lower()

    answers = {
        q["id"]: secplus_learn.CHOICE_LETTERS[q["answer_idx"]]
        for q in secplus_learn.get_quiz(first)
    }
    posted = client.post(
        f"/career/secplus/quiz/{first}/submit",
        json={"answers": answers},
    )
    assert posted.status_code == 200
    body = posted.get_json()
    assert body["ok"] and body["result"]["passed"] and body["result"]["pct"] == 100
    assert body.get("next_lesson")

    # Legacy domain URL still works (redirect)
    legacy = client.get("/career/secplus/domain/d4_operations", follow_redirects=False)
    assert legacy.status_code in (301, 302)

    terms = client.get("/career/secplus/terms")
    assert terms.status_code == 200
    assert b"term bank" in terms.data.lower() or b"Term bank" in terms.data

    career = client.get("/career")
    assert career.status_code == 200
    assert b"Security+ Lab" in career.data
    assert b"/career/secplus" in career.data
    assert b"Prove-it gates" in career.data


def test_secplus_terms_in_glossary_and_hover_map():
    """Sec+ lesson vocabulary is in the dictionary and matchable in-context."""
    import security_acronyms as sa

    abbrs = {e["abbr"] for e in sa.GLOSSARY_ENTRIES}
    assert len(abbrs) == len(sa.GLOSSARY_ENTRIES)

    required = [
        "ZT", "AUP", "CASB", "IaaS", "PaaS", "SaaS", "PBQ", "KQL", "SPL",
        "FP", "TP", "FN", "NIDS", "NIPS", "SOC 2", "MFA", "SIEM", "SOAR",
        "EDR", "BEC", "DLP", "VPN", "VLAN", "PKI", "RTO", "RPO", "BCP",
        "Phishing", "Ransomware", "Privilege Escalation", "Lateral Movement",
        "Password Spray", "Zero Trust" if "Zero Trust" in abbrs else "ZT",
        "Hashing", "Encryption", "Chain of Custody", "Shared Responsibility",
        "Change Management", "Risk Appetite", "Tabletop", "Penetration Test",
        "Vulnerability Scan", "False Positive" if "False Positive" in abbrs else "FP",
        "Conditional Access", "Defense in Depth", "Honeypot", "Legacy Auth",
        "Preventive Control", "Detective Control", "Microsegmentation",
    ]
    missing = [t for t in required if t not in abbrs]
    assert not missing, missing

    payload = sa.hover_payload()
    assert payload["MFA"]["layman"]
    assert payload["ZT"]["id"] == "ZT"
    pairs = sa.hover_match_pairs()
    keys_lower = [k.lower() for k, _ in pairs]
    assert keys_lower == sorted(keys_lower, key=len, reverse=True)
    assert "multi-factor authentication" in keys_lower
    assert "zero trust" in keys_lower
    assert "denial of service" in keys_lower
    for noisy in ("log", "all", "in", "the", "and"):
        assert noisy not in keys_lower


def test_jargon_hover_on_secplus_and_ops_pages(client):
    """Hover payload is on study pages AND ops dashboards (Option C)."""
    _analyst_session(client)

    first = secplus_learn.lesson_ids()[0]
    lesson = client.get(f"/career/secplus/lesson/{first}")
    assert lesson.status_code == 200
    assert b"__BOUNDRY_JARGON" in lesson.data or b"glossary.js" in lesson.data
    assert b"MFA" in lesson.data or b"Preventive" in lesson.data

    glossary = client.get("/glossary")
    assert glossary.status_code == 200
    assert b"gloss-ZT" in glossary.data or b">ZT<" in glossary.data
    assert b"Acceptable Use Policy" in glossary.data
    assert b"Zero Trust" in glossary.data

    cr = client.get("/control-room")
    assert cr.status_code == 200
    assert b"glossary.js" in cr.data or b"__BOUNDRY_JARGON" in cr.data

    siem = client.get("/siem")
    assert siem.status_code == 200
    assert b"glossary.js" in siem.data or b"__BOUNDRY_JARGON" in siem.data

    api = client.get("/api/acronyms")
    assert api.status_code == 200
    body = api.get_json()
    assert "MFA" in body and "aliases" in body["MFA"]
    assert any("multi-factor" in a.lower() for a in body["MFA"]["aliases"])
    assert body["MFA"]["id"] == "MFA"
    assert b'id="gloss-MFA"' in glossary.data


def test_jargon_popover_sticky_and_glossary_deeplink():
    """Hover hide delay + new-tab glossary hash must stay in glossary.js."""
    from pathlib import Path

    js = (Path(__file__).resolve().parents[1] / "static" / "glossary.js").read_text(encoding="utf-8")
    assert "HIDE_DELAY_MS" in js
    delay = None
    for line in js.splitlines():
        if "var HIDE_DELAY_MS" in line:
            digits = "".join(ch for ch in line if ch.isdigit())
            delay = int(digits) if digits else None
            break
    assert delay is not None and 200 <= delay <= 400, delay
    assert 'target="_blank"' in js
    assert 'rel="noopener noreferrer"' in js
    assert "/glossary#gloss-" in js
    assert "relatedIsGlossUi" in js
    assert "jp-below::before" in js
    assert "MutationObserver" in js
    assert 'n.id === "jargon-pop"' in js


def test_cissp_routes_untouched_smoke(client):
    """CISSP hub still loads (Phase 1 Sec+ must not break CISSP)."""
    _analyst_session(client)
    hub = client.get("/cissp")
    assert hub.status_code == 200


def test_secplus_mcq_parallel_form_length_lint():
    """Option C: no severe correct-longest length bias; arity 4; idx in range."""
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    from secplus_mcq_length_lint import is_severe_length_bias, lint_mcq_banks
    import secplus_lessons

    offenders = lint_mcq_banks(
        secplus_lessons.PRACTICE,
        secplus_lessons.QUIZZES,
        hard_fail=False,
    )
    assert not offenders, offenders[:8]

    total = 0
    for bank in (secplus_lessons.PRACTICE, secplus_lessons.QUIZZES):
        for items in bank.values():
            for item in items:
                choices = item.get("choices") or []
                if len(choices) != 4:
                    continue
                total += 1
                idx = int(item["answer_idx"])
                assert 0 <= idx <= 3
                assert not is_severe_length_bias(choices, idx)
    assert total == 460


def test_secplus_mcq_incomplete_choices():
    """No truncated / dangling Help-me or Prove-it choice text."""
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
    from secplus_mcq_length_lint import lint_mcq_incomplete
    import secplus_lessons

    offenders = lint_mcq_incomplete(
        secplus_lessons.PRACTICE,
        secplus_lessons.QUIZZES,
        hard_fail=False,
    )
    assert not offenders, offenders[:12]


if __name__ == "__main__":
    import os
    import tempfile
    from pathlib import Path

    os.environ["SEED_DB"] = "true"
    import app as app_module

    tmp = Path(tempfile.mkdtemp()) / "secplus_smoke.db"
    app_module.DB_PATH = tmp
    app_module.init_db()
    app_module.app.config["TESTING"] = True
    app_module.app.config["WTF_CSRF_ENABLED"] = False
    flask_client = app_module.app.test_client()

    test_secplus_module_spine_and_mixed_grade()
    test_continue_advances_only_after_prove_pass()
    test_secplus_pbq_and_practice_grade()
    test_prove_it_gate_includes_secplus()
    test_saturday_drill_keeps_portfolio_and_has_secplus()
    test_quiz_page_when_no_prove_bank(flask_client)
    test_secplus_routes_and_career_wiring(flask_client)
    test_secplus_terms_in_glossary_and_hover_map()
    test_jargon_hover_on_secplus_and_ops_pages(flask_client)
    test_jargon_popover_sticky_and_glossary_deeplink()
    test_cissp_routes_untouched_smoke(flask_client)
    test_secplus_mcq_parallel_form_length_lint()
    print("SECPLUS_SMOKE_OK")
