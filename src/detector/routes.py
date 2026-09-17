import csv
import io
import json

from flask import (
    Blueprint, render_template, request, redirect, url_for, flash,
    send_file, current_app, abort,
)
from flask_login import login_required, current_user

from models import db, EmailSubmission, AuditLog
from security_utils import limiter, analyst_or_admin_required
from analysis import zero_trust, risk_engine
from analysis.zero_trust import ZeroTrustRejection

detector_bp = Blueprint("detector", __name__, template_folder="../templates/detector")


def _client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr)


@detector_bp.route("/")
@login_required
def dashboard():
    q = EmailSubmission.query
    if not current_user.is_admin:
        q = q.filter_by(user_id=current_user.id)
    submissions = q.order_by(EmailSubmission.created_at.desc()).limit(50).all()

    total = q.count()
    phishing = q.filter_by(verdict="phishing").count()
    suspicious = q.filter_by(verdict="suspicious").count()
    false_positives = q.filter_by(analyst_feedback="false_positive").count()

    common_indicators = {}
    for s in q.order_by(EmailSubmission.created_at.desc()).limit(200).all():
        for ind in s.rule_indicators():
            common_indicators[ind] = common_indicators.get(ind, 0) + 1
    top_indicators = sorted(common_indicators.items(), key=lambda t: t[1], reverse=True)[:8]

    return render_template(
        "detector/dashboard.html", submissions=submissions, total=total,
        phishing=phishing, suspicious=suspicious, false_positives=false_positives,
        top_indicators=top_indicators,
    )


@detector_bp.route("/upload", methods=["GET", "POST"])
@login_required
@limiter.limit("30 per hour")
def upload():
    if request.method == "POST":
        file = request.files.get("email_file")
        if not file or file.filename == "":
            flash("Please choose a .eml or .txt file.", "danger")
            return redirect(url_for("detector.upload"))

        raw_bytes = file.read()
        try:
            result = zero_trust.ingest(
                raw_bytes=raw_bytes,
                filename=file.filename,
                declared_mimetype=file.mimetype,
                user=current_user,
                max_bytes=current_app.config["MAX_CONTENT_LENGTH"],
                allowed_ext=current_app.config["ALLOWED_UPLOAD_EXTENSIONS"],
                allowed_mimetypes=current_app.config["ALLOWED_UPLOAD_MIMETYPES"],
            )
        except ZeroTrustRejection as exc:
            AuditLog.append(
                "ingest_rejected", user_id=current_user.id, username=current_user.username,
                ip_address=_client_ip(), detail=f"gate={exc.gate} reason={exc.reason}",
            )
            flash(f"Submission rejected at Zero-Trust gate {exc.gate}: {exc.reason}", "danger")
            return redirect(url_for("detector.upload"))

        AuditLog.append(
            "ingest_accepted", user_id=current_user.id, username=current_user.username,
            ip_address=_client_ip(), detail=f"gates_passed={result.gates_passed} sha256={result.sha256_hash}",
        )

        scored = risk_engine.score_email(
            subject=result.subject,
            body_text=result.body_text,
            sender_raw=result.sender,
            raw_headers=result.raw_headers,
            attachment_count=len(result.attachment_summaries),
        )

        submission = EmailSubmission(
            user_id=current_user.id,
            original_filename=file.filename,
            sha256_hash=result.sha256_hash,
            sender=result.sender,
            sender_display_name=scored["header_report"]["display_name"],
            subject=result.subject,
            received_headers_summary=json.dumps(list(result.raw_headers.keys())),
            spf_result=scored["header_report"]["spf"],
            dkim_result=scored["header_report"]["dkim"],
            dmarc_result=scored["header_report"]["dmarc"],
            risk_score=scored["risk_score"],
            verdict=scored["verdict"],
            rule_indicators_json=json.dumps(scored["rule_indicators"]),
            ml_probability=scored["ml_probability"],
            ml_explanation_json=json.dumps(scored["ml_explanation"]),
            attachment_summary_json=json.dumps(result.attachment_summaries),
            quarantined=(scored["verdict"] in ("phishing", "suspicious")),
        )
        db.session.add(submission)
        db.session.commit()

        AuditLog.append(
            "scored", user_id=current_user.id, username=current_user.username, ip_address=_client_ip(),
            detail=f"submission_id={submission.id} verdict={submission.verdict} score={submission.risk_score}",
        )
        if submission.quarantined:
            AuditLog.append(
                "quarantine", user_id=current_user.id, username=current_user.username,
                ip_address=_client_ip(), detail=f"submission_id={submission.id} (quarantine-by-default)",
            )

        return redirect(url_for("detector.view_result", submission_id=submission.id))

    return render_template("detector/upload.html")


def _get_owned_submission(submission_id):
    submission = EmailSubmission.query.get_or_404(submission_id)
    if not current_user.is_admin and submission.user_id != current_user.id:
        abort(403)
    return submission


@detector_bp.route("/result/<int:submission_id>")
@login_required
def view_result(submission_id):
    submission = _get_owned_submission(submission_id)
    return render_template("detector/result.html", s=submission)


@detector_bp.route("/result/<int:submission_id>/release", methods=["POST"])
@login_required
@analyst_or_admin_required
def release_quarantine(submission_id):
    submission = _get_owned_submission(submission_id)
    submission.quarantined = False
    db.session.commit()
    AuditLog.append(
        "quarantine_released", user_id=current_user.id, username=current_user.username,
        ip_address=_client_ip(), detail=f"submission_id={submission.id}",
    )
    flash("Submission released from quarantine.", "success")
    return redirect(url_for("detector.view_result", submission_id=submission_id))


@detector_bp.route("/result/<int:submission_id>/feedback", methods=["POST"])
@login_required
@analyst_or_admin_required
def submit_feedback(submission_id):
    submission = _get_owned_submission(submission_id)
    verdict = request.form.get("feedback")
    if verdict not in ("confirmed_phish", "false_positive"):
        abort(400)
    submission.analyst_feedback = verdict
    submission.feedback_notes = request.form.get("notes", "")[:2000]
    db.session.commit()
    AuditLog.append(
        "analyst_feedback", user_id=current_user.id, username=current_user.username,
        ip_address=_client_ip(), detail=f"submission_id={submission.id} feedback={verdict}",
    )
    flash("Feedback recorded. Thank you.", "success")
    return redirect(url_for("detector.view_result", submission_id=submission_id))


@detector_bp.route("/result/<int:submission_id>/export/<fmt>")
@login_required
def export_result(submission_id, fmt):
    submission = _get_owned_submission(submission_id)
    data = {
        "id": submission.id,
        "filename": submission.original_filename,
        "sha256": submission.sha256_hash,
        "sender": submission.sender,
        "subject": submission.subject,
        "spf": submission.spf_result,
        "dkim": submission.dkim_result,
        "dmarc": submission.dmarc_result,
        "risk_score": submission.risk_score,
        "verdict": submission.verdict,
        "ml_probability": submission.ml_probability,
        "rule_indicators": submission.rule_indicators(),
        "ml_explanation": submission.ml_explanation(),
        "attachments": submission.attachment_summary(),
        "created_at": submission.created_at.isoformat(),
    }

    if fmt == "json":
        buf = io.BytesIO(json.dumps(data, indent=2).encode())
        return send_file(buf, mimetype="application/json", as_attachment=True,
                          download_name=f"submission_{submission.id}.json")

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(data.keys())
        writer.writerow([json.dumps(v) if isinstance(v, (list, dict)) else v for v in data.values()])
        mem = io.BytesIO(buf.getvalue().encode())
        return send_file(mem, mimetype="text/csv", as_attachment=True,
                          download_name=f"submission_{submission.id}.csv")

    if fmt == "pdf":
        from detector.pdf_report import build_pdf_report
        pdf_buf = build_pdf_report(data)
        return send_file(pdf_buf, mimetype="application/pdf", as_attachment=True,
                          download_name=f"submission_{submission.id}.pdf")

    abort(400)
