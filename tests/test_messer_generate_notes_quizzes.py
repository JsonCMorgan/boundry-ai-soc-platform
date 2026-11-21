"""Batch resume helpers for Messer notes Help (no Ollama)."""

from __future__ import annotations

import json

from tools.messer_notes_quiz_batch import (
    has_notes_help,
    notes_eligible,
    write_curriculum_atomic,
)


def test_has_notes_help_detects_prefix():
    assert has_notes_help([{"id": "ms_0101_01:notes:help:00"}])
    assert not has_notes_help([{"id": "messer:pe:x:q1"}])


def test_notes_eligible_threshold():
    thin = {"sections": [{"heading": "Course notes", "body": "x" * 100}]}
    ok = {"sections": [{"heading": "Course notes", "body": "x" * 300}]}
    assert notes_eligible(thin) == (False, "thin")
    assert notes_eligible(ok) == (True, "ok")


def test_write_curriculum_atomic(tmp_path):
    p = tmp_path / "701_curriculum.json"
    write_curriculum_atomic(p, {"version": "SY0-701", "lessons": []})
    data = json.loads(p.read_text(encoding="utf-8"))
    assert data["version"] == "SY0-701"
