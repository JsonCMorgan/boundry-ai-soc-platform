"""Messer course notes HTML structure (content preserved)."""

from messer_notes_format import format_notes_body


SAMPLE = """Security controls
•\tSecurity risks are out there
\t– Many different categories and types to consider
•\tAssets are also varied
Deterrent control types
•\tDeterrent
\t– Discourage an intrusion attempt
\t– Does not directly prevent access"""


def test_notes_headings_and_nested_bullets():
    html = format_notes_body(SAMPLE)
    assert "Security controls" in html
    assert "Security risks are out there" in html
    assert "Many different categories" in html
    assert "notes-heading" in html
    assert "notes-sublist" in html
    assert "<ul" in html


def test_transcript_uses_paragraphs():
    html = format_notes_body("Line one.\nLine two.", mode="transcript")
    assert 'class="notes-p"' in html
    assert "notes-heading" not in html
