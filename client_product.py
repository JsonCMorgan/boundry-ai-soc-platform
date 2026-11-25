"""Client product routes: portal, privacy, onboard wizard, deliverables hooks."""

from __future__ import annotations

import json
import os
import secrets
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

import bcrypt
from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

import boundry_deliverables
import ingest_map
import m365_ingest
import tenant_ops
import boundry_audit


def register_client_product_routes(app: Flask) -> None:
    """Attach P1 client-facing and onboard routes to the Flask app."""
    db_run = app.config["BOUNDARY_DB_RUN"]
    db_fetchone = app.config["BOUNDARY_DB_FETCHONE"]
    db_fetchall = app.config["BOUNDARY_DB_FETCHALL"]
    db_insert = app.config["BOUNDARY_DB_INSERT"]
    PH = app.config["BOUNDARY_PH"]
    DATABASE_URL = app.config.get("BOUNDARY_DATABASE_URL", "")
    analyst_required = app.config["BOUNDARY_ANALYST_REQUIRED"]
    login_required = app.config["BOUNDARY_LOGIN_REQUIRED"]
    send_email = app.config["BOUNDARY_SEND_EMAIL"]
    compute_health_score = app.config["BOUNDARY_HEALTH_SCORE"]
    RISK_CONTROLS = app.config["BOUNDARY_RISK_CONTROLS"]
    RISK_INDUSTRIES = app.config["BOUNDARY_RISK_INDUSTRIES"]
    _compute_risk_assessment = app.config["BOUNDARY_RISK_FN"]
    validate_password = app.config["BOUNDARY_VALIDATE_PASSWORD"]
    siem_collector = app.config["BOUNDARY_SIEM"]
    security_log = app.config["BOUNDARY_SECURITY_LOG"]
    generate_report_pdf = app.config.get("BOUNDARY_PDF_FN")

    @app.route("/privacy")
    def privacy_page():
        """Render M7 privacy one-pager in-app."""
        doc = Path(__file__).resolve().parent / "docs" / "PRIVACY_DATA_HANDLING.md"
        text = doc.read_text(encoding="utf-8") if doc.is_file() else "Privacy doc not found."
        return render_template("privacy.html", body=text, role=session.get("role", ""))

    @app.route("/client/status")
    @login_required
    def client_status():
        """Client monitoring heartbeat (no raw SIEM)."""
        if session.get("role") == "analyst":
            return redirect(url_for("control_room"))
        uid = session.get("user_id")
        slug = tenant_ops.resolve_tenant_slug(db_fetchone, PH, uid)
        if DATABASE_URL:
            last_ev = db_fetchone(
                f"SELECT created_at FROM siem_events WHERE client_id = {PH} "
                f"AND simulated = 0 ORDER BY id DESC LIMIT 1",
                (slug,),
            )
            open_findings = db_fetchone(
                f"SELECT COUNT(*) AS n FROM system_findings WHERE client_id = {PH} AND resolved = 0",
                (slug,),
            )
        else:
            last_ev = db_fetchone(
                f"SELECT created_at FROM siem_events WHERE client_id = {PH} "
                f"AND simulated = 0 ORDER BY id DESC LIMIT 1",
                (slug,),
            )
            open_findings = db_fetchone(
                f"SELECT COUNT(*) AS n FROM system_findings WHERE client_id = {PH} AND resolved = 0",
                (slug,),
            )
        last_report = db_fetchone(
            f"SELECT id, created_at, report_type FROM reports WHERE owner_id = {PH} "
            f"AND simulated = 0 ORDER BY id DESC LIMIT 1",
            (uid,),
        )
        ingest_ok = True
        banner = "All clear"
        detail = "Monitoring is active. No open findings require your action."
        if open_findings and int(open_findings.get("n") or 0) > 0:
            banner = "Action recommended"
            detail = (
                f"{open_findings['n']} open item(s) need review. "
                "Your analyst will follow up or check your latest report."
            )
        if not last_ev:
            ingest_ok = False
            banner = "Waiting for data"
            detail = "We have not received events yet. If you just onboarded, allow up to 24 hours."
        else:
            try:
                # Rough stale check: parse sqlite datetime string
                ts = last_ev.get("created_at") or ""
                if ts and " " in ts:
                    seen = datetime.strptime(ts[:19], "%Y-%m-%d %H:%M:%S")
                    if datetime.utcnow() - seen > timedelta(hours=24):
                        banner = "Check connection"
                        detail = "No events in the last 24 hours. Contact your analyst if unexpected."
            except Exception:
                pass
        health = compute_health_score(uid)
        return render_template(
            "client_status.html",
            banner=banner,
            detail=detail,
            ingest_ok=ingest_ok,
            last_event=last_ev,
            last_report=last_report,
            open_count=int(open_findings.get("n") or 0) if open_findings else 0,
            health=health,
            tenant_slug=slug,
            role=session.get("role", "client"),
        )

    @app.route("/analyst/onboard", methods=["GET", "POST"])
    @analyst_required
    def analyst_onboard():
        """Multi-step client onboarding wizard."""
        completion = None
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            email = (request.form.get("email") or "").strip()
            business_name = (request.form.get("business_name") or "").strip()
            industry = (request.form.get("industry") or "professional_services").strip()
            tier = (request.form.get("tier") or "Silver").strip()
            scope = (request.form.get("scope") or "siem").strip()

            if len(username) < 3 or "@" not in email:
                flash("Username and valid email required.", "danger")
                return redirect(url_for("analyst_onboard"))
            if db_fetchone(f"SELECT id FROM users WHERE username = {PH}", (username,)):
                flash(f"Username '{username}' already exists.", "danger")
                return redirect(url_for("analyst_onboard"))

            placeholder_pw = bcrypt.hashpw(secrets.token_urlsafe(32).encode(), bcrypt.gensalt()).decode()
            api_key = secrets.token_urlsafe(32)
            new_id = db_insert(
                f"INSERT INTO users (username, password, role, api_key, email, business_name, industry) "
                f"VALUES ({PH}, {PH}, 'client', {PH}, {PH}, {PH}, {PH})",
                (username, placeholder_pw, api_key, email, business_name, industry),
            )
            slug = tenant_ops.ensure_tenant(
                db_run, db_fetchone, PH, new_id, username,
                display_name=business_name or username,
                tier=tier,
                is_practice=0,
            )
            token = secrets.token_urlsafe(32)
            expires = (datetime.utcnow() + timedelta(hours=48)).strftime("%Y-%m-%d %H:%M:%S")
            db_run(
                f"INSERT INTO password_setup_tokens (token, user_id, expires_at) VALUES ({PH}, {PH}, {PH})",
                (token, new_id, expires),
            )
            app_url = os.environ.get("APP_URL", request.url_root.rstrip("/")).rstrip("/")
            setup_url = f"{app_url}/set-password/{token}"
            ingest_url = f"{app_url}/api/ingest"

            if request.form.get("run_risk") == "on":
                try:
                    employees = int(request.form.get("employees") or 10)
                    annual_revenue = float(request.form.get("annual_revenue") or 0)
                    records = int(request.form.get("records") or 0)
                    downtime = float(request.form.get("downtime_cost_hr") or 0)
                    controls = {k: (request.form.get("ctrl_" + k) == "on") for k, _ in RISK_CONTROLS}
                    result = _compute_risk_assessment(
                        industry, employees, annual_revenue, records, downtime, controls
                    )
                    db_run(
                        f"INSERT INTO risk_assessments (client_id, industry, employees, annual_revenue, "
                        f"records, downtime_cost_hr, controls_json, risk_score, grade, ale, sle, aro, "
                        f"recommended_monthly, analyst_id) VALUES "
                        f"({PH},{PH},{PH},{PH},{PH},{PH},{PH},{PH},{PH},{PH},{PH},{PH},{PH},{PH})",
                        (
                            new_id, industry, employees, annual_revenue, records, downtime,
                            json.dumps(controls), result["score"], result["grade"], result["ale"],
                            result["sle"], result["aro"], result["recommended_monthly"],
                            session.get("user_id"),
                        ),
                    )
                except Exception as exc:
                    security_log.warning(f"ONBOARD_RISK_SKIP err={exc}")

            completion = {
                "username": username,
                "scope": scope,
                "setup_url": setup_url,
                "ingest_url": ingest_url,
                "api_key": api_key,
                "client_id": new_id,
                "slug": slug,
            }
            flash(f"Client '{username}' onboarded.", "success")
            try:
                boundry_audit.log_analyst_audit(
                    db_run, PH,
                    analyst_id=session.get("user_id"),
                    action="client_create",
                    detail=f"onboard username={username} slug={slug}",
                    target_user_id=new_id,
                    ref_id=str(new_id),
                )
            except Exception:
                pass

        return render_template(
            "analyst_onboard.html",
            completion=completion,
            risk_controls=RISK_CONTROLS,
            risk_industries=RISK_INDUSTRIES,
            role=session.get("role"),
        )

    @app.route("/analyst/client/<int:client_id>/risk-assessment/pdf")
    @analyst_required
    def risk_assessment_pdf(client_id: int):
        """Export saved risk assessment as PDF."""
        if not generate_report_pdf:
            abort(501)
        saved = db_fetchone(f"SELECT * FROM risk_assessments WHERE client_id = {PH}", (client_id,))
        if not saved:
            abort(404)
        client = db_fetchone(
            f"SELECT username, business_name FROM users WHERE id = {PH}", (client_id,)
        )
        title = client.get("business_name") or client.get("username") if client else "Client"
        md = (
            f"# Risk snapshot — {title}\n\n"
            f"Grade: **{saved.get('grade')}** | Score: {saved.get('risk_score')}\n\n"
            f"Annual loss exposure: ${saved.get('ale'):,.0f}\n"
            f"Recommended monthly: ${saved.get('recommended_monthly'):,.0f}\n"
        )
        pdf_bytes = generate_report_pdf(
            report_id=client_id,
            created_at=saved.get("created_at") or "",
            threat_count=0,
            event_count=0,
            content_md=md,
            simulated=False,
        )
        from flask import Response

        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="Boundry_Risk_{client_id}.pdf"'
            },
        )

    @app.route("/analyst/syslog-sources", methods=["GET", "POST"])
    @analyst_required
    def analyst_syslog_sources():
        """CRUD syslog IP → tenant mappings."""
        if request.method == "POST":
            src_ip = (request.form.get("src_ip") or "").strip()
            client_id = (request.form.get("client_id") or "").strip()
            label = (request.form.get("label") or "").strip()
            if src_ip and client_id:
                dup = db_fetchone(
                    f"SELECT id FROM syslog_sources WHERE src_ip = {PH}", (src_ip,)
                )
                if dup:
                    db_run(
                        f"UPDATE syslog_sources SET client_id = {PH}, label = {PH} WHERE id = {PH}",
                        (client_id, label, dup["id"]),
                    )
                else:
                    db_run(
                        f"INSERT INTO syslog_sources (src_ip, client_id, label) "
                        f"VALUES ({PH}, {PH}, {PH})",
                        (src_ip, client_id, label),
                    )
                flash("Syslog source saved.", "success")
        rows = db_fetchall(
            "SELECT id, src_ip, client_id, label, enabled FROM syslog_sources ORDER BY id DESC"
        )
        tenants = db_fetchall(
            f"SELECT client_id, display_name FROM mssp_tenants WHERE is_practice = 0 ORDER BY client_id"
        )
        return render_template(
            "analyst_syslog_sources.html",
            rows=rows or [],
            tenants=tenants or [],
            role=session.get("role"),
        )

    @app.route("/api/m365/ingest", methods=["POST"])
    def api_m365_ingest():
        """Phase-1 M365 audit JSON upload keyed like /api/ingest."""
        api_key = request.headers.get("X-API-Key", "").strip()
        if not api_key:
            return jsonify(error="Missing X-API-Key"), 401
        user = boundry_audit.resolve_ingest_api_key(db_fetchone, PH, api_key)
        if not user:
            return jsonify(error="Invalid API key"), 401
        payload = request.get_json(silent=True)
        records = m365_ingest.parse_audit_payload(payload)
        if not records:
            return jsonify(error="No audit records in body"), 400
        slug = tenant_ops.resolve_tenant_slug(db_fetchone, PH, user["id"])
        n = m365_ingest.ingest_m365_records(records, slug, siem_collector.ingest_event)
        return jsonify(status="ok", ingested=n), 201