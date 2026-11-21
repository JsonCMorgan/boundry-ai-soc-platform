"""Messer curriculum spine (no copyrighted body in repo)."""

from __future__ import annotations

import json
import os
from pathlib import Path


def test_curriculum_json_exists_and_shape():
    p = Path(__file__).resolve().parents[1] / "content" / "private" / "messer" / "curriculum" / "701_curriculum.json"
    if not p.is_file():
        return  # local Jason machine only
    data = json.loads(p.read_text(encoding="utf-8"))
    assert data.get("version") == "SY0-701"
    assert len(data.get("lessons") or []) >= 100


def test_help_and_prove_split_session_pool_without_overlap():
    from tools.messer_build_curriculum import _split_help_prove

    pool = [{"item_id": f"q{i}", "stem": f"session {i}"} for i in range(2)]
    help_raw, prove_raw = _split_help_prove(pool)
    assert len(help_raw) == 1
    assert len(prove_raw) == 1
    assert help_raw[0]["item_id"] != prove_raw[0]["item_id"]


def test_help_and_prove_do_not_pull_from_other_sessions():
    from tools.messer_build_curriculum import _split_help_prove

    pool = [{"item_id": "only_here", "stem": "x"}]
    help_raw, prove_raw = _split_help_prove(pool)
    assert len(help_raw) == 1
    assert prove_raw == []


def test_apply_notes_quizzes_writes_notes_prove(monkeypatch):
    import os

    from tools.messer_build_curriculum import _apply_notes_quizzes

    os.environ["MESSER_QUIZ_FROM_NOTES"] = "1"
    payload = {
        "lessons": [
            {
                "id": "ms_test_01",
                "title": "Test",
                "objective_ref": "1.1",
                "sections": [{"heading": "Course notes", "body": "x" * 300}],
                "has_help_me": False,
                "has_prove": False,
            }
        ],
        "practice": {},
        "quizzes": {},
    }

    def fake_help(**kwargs):
        return [{"id": "ms_test_01:notes:help:00", "prompt": "H?", "choices": ["a", "b", "c", "d"], "answer_idx": 0}]

    def fake_prove(**kwargs):
        return [
            {"id": f"ms_test_01:notes:prove:{i:02d}", "q": f"Q{i}?", "choices": ["a", "b", "c", "d"], "answer_idx": 0}
            for i in range(5)
        ]

    import notes_quiz_generator

    monkeypatch.setattr(notes_quiz_generator, "generate_notes_help", fake_help)
    monkeypatch.setattr(notes_quiz_generator, "generate_notes_prove", fake_prove)
    n = _apply_notes_quizzes(payload, lesson_filter="ms_test_01")
    assert n == 1
    assert ":notes:help:" in payload["practice"]["ms_test_01"][0]["id"]
    assert len(payload["quizzes"]["ms_test_01"]) == 5


def test_secplus_learn_switches_with_flag():
    os.environ["ENABLE_MESSER_LAYER"] = "1"
    import importlib
    import messer_curriculum
    import secplus_learn

    importlib.reload(messer_curriculum)
    importlib.reload(secplus_learn)
    if not messer_curriculum.is_ready():
        return
    assert len(secplus_learn.active_lessons()) >= 100
    assert secplus_learn.get_lesson("ms_0101_01") is not None
