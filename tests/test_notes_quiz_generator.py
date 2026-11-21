"""Notes quiz JSON parsing (no Ollama in CI)."""

import json

import pytest

from notes_quiz_guards import _assert_mcq_concepts, validate_notes_mcq
from notes_quiz_generator import _extract_json_blob, _validate_mcq


def test_extract_json_from_fence():
    raw = 'Here is JSON:\n```json\n{"help_me": [], "prove_it": []}\n```'
    data = _extract_json_blob(raw)
    assert "help_me" in data


def test_validate_mcq_ok():
    mcq = _validate_mcq({
        "prompt": "Which control type blocks access?",
        "choices": ["Detective", "Preventive", "Corrective", "Deterrent"],
        "answer_idx": 1,
        "explain": "Correct. Preventive stops the event.",
    }, "help")
    assert mcq["answer_idx"] == 1
    assert len(mcq["choices"]) == 4


def test_non_repudiation_rejects_inverted_deny_answer():
    bad = {
        "prompt": "What is non-repudiation?",
        "choices": [
            "The ability to deny what you've said",
            "Integrity only",
            "Availability only",
            "Confidentiality only",
        ],
        "answer_idx": 0,
        "explain": "Correct. Non-repudiation is the ability to deny what you've said.",
    }
    with pytest.raises(ValueError):
        _assert_mcq_concepts(bad)


def test_validate_mcq_rejects_dupe_choices():
    with pytest.raises(ValueError):
        _validate_mcq({
            "prompt": "Test?",
            "choices": ["A", "A", "B", "C"],
            "answer_idx": 0,
        }, "help")
