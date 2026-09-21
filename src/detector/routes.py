import csv
import io
import json
from collections import OrderedDict
from datetime import timedelta

from flask import (
    Blueprint, render_template, request, redirect, url_for, flash,
    send_file, current_app, abort,
)
from flask_login import login_required, current_user

from models import db, EmailSubmission, ExtractedIndicator, AuditLog, utcnow
from security_utils import limiter, analyst_or_admin_required
from analysis import zero_trust, risk_engine, threat_intel
from analysis.explanations import defang
from analysis.url_analysis import analyse_url
from analysis.zero_trust import ZeroTrustRejection

detector_bp = Blueprint("detector", __name__, template_folder="../templates/detector")

MAX_INDICATORS = 20
FLAGGED_VERDICTS = ("phishing", "suspicious")
_CSV_DANGEROUS_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr)


def _csv_safe(value):
    """Neutralise spreadsheet formula injection: sender/subject are attacker-controlled,
    and a cell starting with = + - @ would be executed by Excel/LibreOffice."""
    if isinstance(value, (list, dict)):
        value = json.dumps(value)
    if isinstance(value, str) and value.startswith(_CSV_DANGEROUS_PREFIXES):
        return "'" + value
    return value


def _visible_query():
    q = EmailSubmission.query
    if not current_user.is_admin:
        q = q.filter_by(user_id=current_user.id)
    return q


def _pct(part, whole):
    return round(100.0 * part / whole, 1) if whole else 0.0


@detector_bp.route("/")
@login_required
def dashboard():
    q = _visible_query()
    total = q.count()
    phishing = q.filter_by(verdict="phishing").count()
    suspicious = q.filter_by(verdict="suspicious").count()
    legitimate = q.filter_by(verdict="legitimate").count()
    flagged = phishing + suspicious

    confirmed = q.filter_by(analyst_feedback="confirmed_phish").count()
    false_positives = q.filter_by(analyst_feedback="false_positive").count()
    reviewed = confirmed + false_positives
    pending_review = q.filter(
        EmailSubmission.verdict.in_(FLAGGED_VERDICTS), EmailSubmission.analyst_feedback.is_(None)
    ).count()

    recent = q.order_by(EmailSubmission.created_at.desc()).limit(200).all()
    common_indicators = {}
    for s in recent:
        for ind in s.rule_indicators():
            common_indicators[ind] = common_indicators.get(ind, 0) + 1
    top_indicators = sorted(common_indicators.items(), key=lambda t: t[1], reverse=True)[:8]

    today = utcnow().date()
    days = OrderedDict((today - timedelta(days=n), {"total": 0, "flagged": 0}) for n in range(13, -1, -1))
    for s in q.filter(EmailSubmission.created_at >= utcnow() - timedelta(days=14)).all():
        bucket = days.get(s.created_at.date())
        if bucket:
            bucket["total"] += 1
            bucket["flagged"] += int(s.verdict in FLAGGED_VERDICTS)
    trend = [{"day": d.strftime("%d %b"), **v} for d, v in days.items()]

    intel_q = db.session.query(ExtractedIndicator).join(EmailSubmission)
    if not current_user.is_admin:
        intel_q = intel_q.filter(EmailSubmission.user_id == current_user.id)
    intel_checked = intel_q.filter(ExtractedIndicator.intel_verdict.isnot(None)).count()
    intel_bad = intel_q.filter(ExtractedIndicator.intel_verdict.in_(("malicious", "suspicious"))).count()

    stats = {
        "total": total, "phishing": phishing, "suspicious": suspicious, "legitimate": legitimate,
        "detection_rate": _pct(flagged, total),
        "confirmed": confirmed, "false_positives": false_positives, "reviewed": reviewed,
        "fp_rate": _pct(false_positives, reviewed), "precision_est": _pct(confirmed, reviewed),
        "pending_review": pending_review,
        "intel_checked": intel_checked, "intel_bad": intel_bad,
        "verdict_pct": {"phishing": _pct(phishing, total), "suspicious": _pct(suspicious, total),
                        "legitimate": _pct(legitimate, total)},
    }
    return render_template(
        "detector/dashboard.html", submissions=recent[:50], stats=stats, top_indicators=top_indicators,
        trend=trend, trend_max=max([d["total"] for d in trend] + [1]),
    )


def _is_listed(findings):
    return "blocklisted_domain" in findings or "known_malicious_domain" in findings


def _store_indicators(submission, url_report, attachments):
    """Persist the domains, suspicious URLs and attachment hashes found in a submission
    so an analyst can later run threat-intel lookups against them."""
    per_domain = OrderedDict()
    for result in url_report["results"]:
        domain = result["registered_domain"]
        if domain:
            entry = per_domain.setdefault(domain, {"findings": set(), "blocklisted": False})
            entry["findings"].update(result["findings"])
            entry["blocklisted"] = entry["blocklisted"] or _is_listed(result["findings"])

    for domain, entry in list(per_domain.items())[:MAX_INDICATORS]:
        db.session.add(ExtractedIndicator(
            submission=submission, kind="domain", value=domain[:255],
            findings_json=json.dumps(sorted(entry["findings"])), blocklisted=entry["blocklisted"],
        ))

    flagged_urls = [r for r in url_report["results"] if r["findings"]]
    for result in flagged_urls[:MAX_INDICATORS]:
        db.session.add(ExtractedIndicator(
            submission=submission, kind="url", value=result["url"][:1000],
            findings_json=json.dumps(result["findings"]),
            blocklisted=_is_listed(result["findings"]),
            redirect_target=(result.get("redirect_target") or "")[:255] or None,
        ))

    for attachment in attachments[:MAX_INDICATORS]:
        db.session.add(ExtractedIndicator(
            submission=submission, kind="attachment_hash", value=attachment["sha256"], findings_json="[]",
        ))


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
            rule_score=scored["rule_score_pct"],
            text_probability=scored["text_probability"],
            structured_probability=scored["structured_probability"],
            ml_explanation_json=json.dumps(scored["ml_explanation"]),
            attachment_summary_json=json.dumps(result.attachment_summaries),
            quarantined=(scored["verdict"] in FLAGGED_VERDICTS),
        )
        db.session.add(submission)
        _store_indicators(submission, scored["url_report"], result.attachment_summaries)
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
    submission = db.session.get(EmailSubmission, submission_id)
    if submission is None:
        abort(404)
    if not current_user.is_admin and submission.user_id != current_user.id:
        abort(403)
    return submission


@detector_bp.route("/result/<int:submission_id>")
@login_required
def view_result(submission_id):
    submission = _get_owned_submission(submission_id)
    explanations = submission.ml_explanation()
    return render_template(
        "detector/result.html", s=submission,
        structured_terms=[e for e in explanations if e.get("source") != "text"],
        text_terms=[e for e in explanations if e.get("source") == "text"],
        intel_configured=bool(current_app.config.get("VIRUSTOTAL_API_KEY")),
        resolver_enabled=bool(current_app.config.get("ENABLE_REDIRECT_RESOLVER")),
    )


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
    if verdict == "false_positive":
        submission.quarantined = False
    db.session.commit()
    AuditLog.append(
        "analyst_feedback", user_id=current_user.id, username=current_user.username,
        ip_address=_client_ip(), detail=f"submission_id={submission.id} feedback={verdict}",
    )
    flash("Feedback recorded. Thank you.", "success")
    return redirect(url_for("detector.view_result", submission_id=submission_id))


# --------------------------------------------------------------------------
# Analyst-triggered threat intelligence (never runs automatically on ingest)
# --------------------------------------------------------------------------
_SEVERITY = {"unknown": 0, "clean": 1, "suspicious": 2, "malicious": 3}


def _combined_intel_verdict(intel):
    verdicts = []
    if "virustotal" in intel:
        verdicts.append(intel["virustotal"].get("verdict", "unknown"))
    chain = intel.get("redirect_chain")
    if chain and chain.get("final_findings"):
        verdicts.append("suspicious")
    elif chain:
        verdicts.append("clean")
    return max(verdicts, key=lambda v: _SEVERITY.get(v, 0)) if verdicts else None


def _worth_resolving(indicator):
    return any(f in ("url_shortener", "open_redirect_parameter", "nested_url_in_url") for f in indicator.findings())


@detector_bp.route("/result/<int:submission_id>/threat-intel", methods=["POST"])
@login_required
@analyst_or_admin_required
@limiter.limit("20 per hour")
def run_threat_intel(submission_id):
    submission = _get_owned_submission(submission_id)
    api_key = current_app.config.get("VIRUSTOTAL_API_KEY")
    resolver_on = current_app.config.get("ENABLE_REDIRECT_RESOLVER")
    if not api_key and not resolver_on:
        flash("No external threat-intel source is configured. Set VIRUSTOTAL_API_KEY and/or "
              "ENABLE_REDIRECT_RESOLVER=true in .env (see README).", "warning")
        return redirect(url_for("detector.view_result", submission_id=submission_id))

    budget = current_app.config.get("THREAT_INTEL_MAX_LOOKUPS", 8)
    used, errors, worst = 0, [], "unknown"
    for indicator in submission.indicators:
        if used >= budget:
            break
        intel = indicator.intel()
        try:
            if api_key and indicator.kind == "domain":
                intel["virustotal"] = threat_intel.lookup_domain(indicator.value, api_key)
            elif api_key and indicator.kind == "attachment_hash":
                intel["virustotal"] = threat_intel.lookup_file_hash(indicator.value, api_key)
            elif resolver_on and indicator.kind == "url" and _worth_resolving(indicator):
                chain = threat_intel.resolve_redirect_chain(indicator.value)
                final = analyse_url(chain["final_url"])
                chain["final_findings"] = [f for f in final["findings"] if f != "no_tls"]
                intel["redirect_chain"] = chain
            else:
                continue
        except threat_intel.ThreatIntelError as exc:
            errors.append(f"{indicator.kind} {defang(indicator.value)[:60]}: {exc}")
            if "rate limit" in str(exc) or "rejected the API key" in str(exc):
                break
            used += 1
            continue
        used += 1
        indicator.intel_json = json.dumps(intel)
        indicator.intel_verdict = _combined_intel_verdict(intel)
        indicator.intel_checked_at = utcnow()
        if _SEVERITY.get(indicator.intel_verdict, 0) > _SEVERITY[worst]:
            worst = indicator.intel_verdict

    if worst == "malicious":
        submission.quarantined = True
    db.session.commit()

    AuditLog.append(
        "threat_intel_lookup", user_id=current_user.id, username=current_user.username, ip_address=_client_ip(),
        detail=f"submission_id={submission.id} lookups={used} worst={worst} errors={len(errors)}",
    )
    for message in errors[:3]:
        flash(f"Lookup problem - {message}", "warning")
    if used:
        flash(f"Threat-intel lookup finished ({used} indicator(s) checked). Worst result: {worst}.",
              "danger" if worst == "malicious" else "success")
    return redirect(url_for("detector.view_result", submission_id=submission_id))


# --------------------------------------------------------------------------
# False-positive review workflow
# --------------------------------------------------------------------------
@detector_bp.route("/review")
@login_required
@analyst_or_admin_required
def review_queue():
    view = request.args.get("view", "pending")
    base = _visible_query()
    counts = {
        "pending": base.filter(EmailSubmission.verdict.in_(FLAGGED_VERDICTS),
                               EmailSubmission.analyst_feedback.is_(None)).count(),
        "false_positive": base.filter_by(analyst_feedback="false_positive").count(),
        "confirmed_phish": base.filter_by(analyst_feedback="confirmed_phish").count(),
    }
    if view in ("false_positive", "confirmed_phish"):
        q = base.filter_by(analyst_feedback=view).order_by(EmailSubmission.created_at.desc())
    else:
        view = "pending"
        q = base.filter(EmailSubmission.verdict.in_(FLAGGED_VERDICTS),
                        EmailSubmission.analyst_feedback.is_(None)).order_by(EmailSubmission.risk_score.desc())
    return render_template("detector/review.html", items=q.limit(200).all(), view=view, counts=counts)


@detector_bp.route("/review/export.csv")
@login_required
@analyst_or_admin_required
def export_review_feedback():
    rows = _visible_query().filter(EmailSubmission.analyst_feedback.isnot(None)) \
        .order_by(EmailSubmission.created_at.desc()).limit(5000).all()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "sha256", "subject", "sender", "verdict", "risk_score", "ml_probability",
                     "analyst_feedback", "feedback_notes", "created_at"])
    for s in rows:
        writer.writerow([_csv_safe(v) for v in (
            s.id, s.sha256_hash, s.subject, s.sender, s.verdict, s.risk_score, s.ml_probability,
            s.analyst_feedback, s.feedback_notes, s.created_at.isoformat())])
    return send_file(io.BytesIO(buf.getvalue().encode()), mimetype="text/csv", as_attachment=True,
                     download_name="analyst_feedback.csv")


# --------------------------------------------------------------------------
# Exports
# --------------------------------------------------------------------------
def _submission_dict(submission):
    return {
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
        "rule_score": submission.rule_score,
        "ml_probability": submission.ml_probability,
        "text_probability": submission.text_probability,
        "structured_probability": submission.structured_probability,
        "quarantined": submission.quarantined,
        "analyst_feedback": submission.analyst_feedback,
        "feedback_notes": submission.feedback_notes,
        "rule_indicators": submission.rule_indicators(),
        "ml_explanation": submission.ml_explanation(),
        "attachments": submission.attachment_summary(),
        "indicators": [
            {"kind": i.kind, "value": i.value, "findings": i.findings(), "blocklisted": i.blocklisted,
             "redirect_target": i.redirect_target, "intel_verdict": i.intel_verdict, "intel": i.intel()}
            for i in submission.indicators
        ],
        "created_at": submission.created_at.isoformat(),
    }


@detector_bp.route("/result/<int:submission_id>/export/<fmt>")
@login_required
def export_result(submission_id, fmt):
    submission = _get_owned_submission(submission_id)
    data = _submission_dict(submission)

    if fmt == "json":
        buf = io.BytesIO(json.dumps(data, indent=2).encode())
        return send_file(buf, mimetype="application/json", as_attachment=True,
                         download_name=f"submission_{submission.id}.json")

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(data.keys())
        writer.writerow([_csv_safe(v) for v in data.values()])
        mem = io.BytesIO(buf.getvalue().encode())
        return send_file(mem, mimetype="text/csv", as_attachment=True,
                         download_name=f"submission_{submission.id}.csv")

    if fmt == "pdf":
        from detector.pdf_report import build_pdf_report
        pdf_buf = build_pdf_report(data)
        return send_file(pdf_buf, mimetype="application/pdf", as_attachment=True,
                         download_name=f"submission_{submission.id}.pdf")

    abort(400)


@detector_bp.route("/export/all/<fmt>")
@login_required
def export_all(fmt):
    rows = _visible_query().order_by(EmailSubmission.created_at.desc()).limit(5000).all()
    if fmt == "json":
        payload = json.dumps([_submission_dict(s) for s in rows], indent=2)
        return send_file(io.BytesIO(payload.encode()), mimetype="application/json", as_attachment=True,
                         download_name="submissions.json")
    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        columns = ["id", "created_at", "filename", "sha256", "sender", "subject", "verdict", "risk_score",
                   "rule_score", "text_probability", "structured_probability", "quarantined", "analyst_feedback"]
        writer.writerow(columns)
        for s in rows:
            record = _submission_dict(s)
            writer.writerow([_csv_safe(record[c]) for c in columns])
        return send_file(io.BytesIO(buf.getvalue().encode()), mimetype="text/csv", as_attachment=True,
                         download_name="submissions.csv")
    abort(400)
