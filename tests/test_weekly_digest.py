"""Weekly digest deliverable tests (GAP-015)."""


def test_weekly_digest_html_skips_empty(monkeypatch):
    import boundry_deliverables

    subject, html = boundry_deliverables.build_weekly_digest_html(
        lambda *a, **k: [],
        "?",
        False,
        1,
        "acme",
        "http://localhost:5000",
        {"score": 90, "color": "#00b432"},
    )
    assert "acme" in subject
    assert "clear" in html.lower() or "No security" in html


def test_build_monthly_summary_has_severity_section():
    import boundry_deliverables

    def _fetch(sql, params=()):
        if "siem_events" in sql:
            return [{"severity": "HIGH"}, {"severity": "INFO"}]
        if "system_findings" in sql:
            return []
        return []

    md, threats, events = boundry_deliverables.build_monthly_summary_markdown(
        _fetch, "?", False, 1, "acme", "acme"
    )
    assert "HIGH" in md
    assert threats == 1
    assert events == 2