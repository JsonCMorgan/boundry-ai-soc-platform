"""Structured Help-me feedback parsing."""

from practice_feedback import build_practice_review, parse_messer_incorrect_answers, prove_item_explain
from practice_hints import build_practice_hint, resolve_practice_hint
from practice_scenario_context import build_scenario_context
from practice_text_format import format_reading_block, format_lead_block


SAMPLE = """The incorrect answers:
A. Preventive
A preventive control physically limits access to a device or area.
C. Corrective
A corrective control can actively work to mitigate any damage.
D. Detective
A detective control may not prevent access, but it can identify and record
any intrusion attempts.
E. Compensating
A compensating security control does not prevent an attack.
F. Directive
A directive control relies on security compliance from the end users."""


def test_parse_filters_to_used_letters_only_in_review():
    parsed = parse_messer_incorrect_answers(SAMPLE)
    assert "A" in parsed
    assert "E" in parsed
    review = build_practice_review(
        choices=["Preventive", "Deterrent", "Corrective", "Detective"],
        answer_idx=1,
        picked_letter="D",
        explain_raw=SAMPLE,
        correct_explain="Deterrent — A login banner discourages unauthorized use.",
    )
    letters = [s["letter"] for s in review["sections"]]
    assert letters[0] == "D"
    assert letters[-1] == "B"
    assert "E" not in letters
    assert "F" not in letters
    assert review["sections"][0]["role"] == "your_pick"


def test_login_banner_scenario_defines_term_first():
    ctx = build_scenario_context(
        "What kind of security control is associated with a login banner?",
        "ms_0001_01",
    )
    assert ctx is not None
    assert "login banner" in ctx["text"].lower()
    assert "sign in" in ctx["text"].lower() or "before" in ctx["text"].lower()


def test_format_reading_block_splits_paragraphs():
    block = format_reading_block(
        "Detective — A detective control may not prevent access, but it can identify "
        "and record any intrusion attempts. It watches after the fact.",
        fallback_term="Detective",
        role="your_pick",
    )
    assert block["term"] == "Detective"
    assert block["role_note"]
    assert len(block["lines"]) >= 1


def test_format_lead_block_splits_headline():
    lead = format_lead_block(
        "You picked D. Detective. Start with why that misses this scenario, then compare."
    )
    assert "Detective" in lead["headline"]
    assert lead["sub"]


def test_login_banner_hint_is_tailored():
    hint = build_practice_hint(
        prompt="What kind of security control is associated with a login banner?",
        choices=["Preventive", "Deterrent", "Corrective", "Detective"],
        answer_idx=1,
        correct_explain=(
            "Deterrent — A deterrent control does not directly stop an attack, "
            "but it may discourage an action."
        ),
    )
    assert "Re-read the course notes" not in hint
    assert "login banner" in hint.lower()
    assert "deterrent" in hint.lower()


def test_resolve_replaces_generic_stored_hint():
    h = resolve_practice_hint({
        "hint": "Re-read the course notes for this session.",
        "prompt": "What kind of security control is associated with a login banner?",
        "choices": ["Preventive", "Deterrent", "Corrective", "Detective"],
        "answer_idx": 1,
        "correct_explain": "Deterrent — discourages an action.",
    })
    assert "login banner" in h.lower()


def test_prove_item_explain_wrong_does_not_start_with_correct():
    item = {
        "q": "Pick the deterrent control.",
        "choices": ["Preventive", "Deterrent", "Corrective", "Detective"],
        "answer_idx": 1,
        "explain": "Correct. A login banner discourages unauthorized use.",
    }
    wrong = prove_item_explain(item, "D", ok=False)
    assert not wrong.lower().startswith("correct.")
    assert not wrong.rstrip().lower().endswith("correct.")
    assert "best answer: b" in wrong.lower()
    assert "you picked d" in wrong.lower()
    assert "login banner" in wrong.lower()
    right = prove_item_explain(item, "B", ok=True)
    assert right.startswith("Correct.")


def test_prove_item_explain_strips_duplicate_choice_letter():
    item = {
        "q": "Fence type?",
        "choices": ["A. Chain link", "B. Opaque with razor wire", "C. Picket", "D. None"],
        "answer_idx": 0,
        "explain": "Correct. Chain link is common for perimeter.",
    }
    wrong = prove_item_explain(item, "B", ok=False)
    assert "B. B." not in wrong
    assert "you picked b" in wrong.lower()


def test_correct_answer_first_when_no_pick():
    review = build_practice_review(
        choices=["A", "B"],
        answer_idx=0,
        picked_letter="",
        explain_raw="",
        correct_explain="Because A fits.",
    )
    assert review["sections"][-1]["role"] == "correct"
