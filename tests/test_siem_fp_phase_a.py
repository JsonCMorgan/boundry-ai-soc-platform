"""SIEM Phase A: firewall matrix, ingest tunes, FP templates."""
from __future__ import annotations

import sqlite3

import siem_fp_templates
import siem_ingest_tunes


def test_classify_firewall_public_background():
    sev, etype, corr = siem_ingest_tunes.classify_firewall_drop(
        "8.8.8.8", "10.0.0.2", "54321"
    )
    assert sev == "INFO"
    assert etype == "firewall_block_background"
    assert corr is False


def test_classify_firewall_public_risky():
    sev, etype, corr = siem_ingest_tunes.classify_firewall_drop(
        "8.8.8.8", "10.0.0.2", "445"
    )
    assert sev == "HIGH"
    assert etype == "firewall_block"
    assert corr is True


def test_classify_firewall_lan_non_risky():
    sev, etype, corr = siem_ingest_tunes.classify_firewall_drop(
        "10.0.0.50", "10.0.0.2", "9999"
    )
    assert sev == "MEDIUM"
    assert etype == "firewall_block"
    assert corr is True


def test_tune_windows_nep_benign():
    msg = "Service Name:  NEP1wapi6t Service File Name:  C:\\Program Files\\NordVPN\\x.exe"
    tune = siem_ingest_tunes.tune_windows_event(7045, msg)
    assert tune is not None
    assert tune.event_type == "service_installed_benign"
    assert tune.correlate is False


def test_tune_windows_unknown_service():
    msg = "Service Name:  EvilPersist Service File Name:  C:\\Temp\\evil.exe"
    assert siem_ingest_tunes.tune_windows_event(7045, msg) is None


def _mini_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    ph = "?"
    conn.execute(
        "CREATE TABLE siem_suppression ("
        "id INTEGER PRIMARY KEY, suppress_type TEXT, value TEXT, "
        "reason TEXT, added_by TEXT)"
    )
    conn.execute(
        "CREATE TABLE siem_events ("
        "id INTEGER PRIMARY KEY, src_ip TEXT, dismissed INTEGER DEFAULT 0)"
    )
    conn.execute(
        "CREATE TABLE system_findings ("
        "id INTEGER PRIMARY KEY, title TEXT, description TEXT, resolved INTEGER DEFAULT 0, "
        "resolved_at TEXT, resolution_reason TEXT, resolution_notes TEXT, resolved_by TEXT)"
    )
    conn.execute(
        "INSERT INTO system_findings (id, title, description, resolved) "
        "VALUES (1, '[SIEM] Firewall Port Scan — 203.0.113.55', 'Correlation trigger', 0)"
    )
    conn.execute(
        "INSERT INTO siem_events (src_ip, dismissed) VALUES ('203.0.113.55', 0)"
    )
    conn.commit()

    def fetchone(sql, params=()):
        cur = conn.execute(sql, params)
        row = cur.fetchone()
        return dict(row) if row else None

    def fetchall(sql, params=()):
        cur = conn.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]

    def run(sql, params=()):
        conn.execute(sql, params)
        conn.commit()

    return conn, ph, fetchone, fetchall, run  # type: ignore


def test_fp_template_internet_port_scan():
    conn, ph, fetchone, fetchall, run = _mini_db()  # type: ignore
    result = siem_fp_templates.apply_template(
        "internet_port_scan",
        1,
        db_fetchone=fetchone,
        db_fetchall=fetchall,
        db_run=run,
        ph=ph,
        added_by="test",
    )
    assert result["ok"] is True
    assert result["suppressed"] is True
    assert result["finding_resolved"] is True
    row = fetchone("SELECT resolved, resolution_reason FROM system_findings WHERE id=?", (1,))
    assert row["resolved"] == 1
    assert row["resolution_reason"] == "false_positive"
    sup = fetchone("SELECT value FROM siem_suppression WHERE value=?", ("203.0.113.55",))
    assert sup is not None
    conn.close()


def test_fp_template_documentation_ip():
    conn, ph, fetchone, fetchall, run = _mini_db()  # type: ignore
    run(
        "UPDATE system_findings SET title=? WHERE id=?",
        ("[SIEM] Brute Force Login — 203.0.113.99", 1),
    )
    result = siem_fp_templates.apply_template(
        "documentation_test_ip",
        1,
        db_fetchone=fetchone,
        db_fetchall=fetchall,
        db_run=run,
        ph=ph,
    )
    assert result["ok"] is True
    conn.close()
