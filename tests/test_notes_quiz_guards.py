"""Notes quiz guard rules."""

import pytest

from notes_quiz_guards import validate_notes_mcq, validate_prove_bank


def test_non_repudiation_rejects_inverted_deny():
    bad = {
        "prompt": "What is non-repudiation?",
        "choices": ["The ability to deny what you've said", "b", "c", "d"],
        "answer_idx": 0,
        "explain": "Correct. ability to deny.",
    }
    with pytest.raises(ValueError):
        validate_notes_mcq(bad)


def test_prove_bank_requires_min_five():
    bank = [
        {"id": "x:notes:prove:00", "q": "Q?", "choices": ["a", "b", "c", "d"], "answer_idx": 0, "explain": "ok"}
    ]
    with pytest.raises(ValueError):
        validate_prove_bank(bank, min_count=5)


def test_sensor_large_area_requires_microwave():
    notes = "Sensors\nMicrowave\nDetects movement across large areas\nUltrasonic\nSend ultrasonic signals"
    bad = {
        "q": "Which sensor for motion in a large area?",
        "choices": ["Infrared", "Pressure", "Microwave", "Ultrasonic"],
        "answer_idx": 3,
        "explain": "x",
    }
    with pytest.raises(ValueError, match="microwave"):
        validate_notes_mcq(bad, notes=notes)
