import csv
import io
import json
from collections import Counter, OrderedDict
from datetime import datetime, time as dtime, timedelta
from math import ceil

from flask import (
    Blueprint, render_template, request, redirect, url_for, flash,
    send_file, current_app, abort,
)
from flask_login import login_required, current_user
from sqlalchemy import func, or_

from models import db, EmailSubmission, ExtractedIndicator, AuditLog, utcnow
from security_utils import limiter, analyst_or_admin_required
from analysis import zero_trust, risk_engine, threat_intel
from analysis.explanations import brand_display, defang, indicator_title
from analysis.url_analysis import analyse_url
from analysis.zero_trust import ZeroTrustRejection
from detector import pasted, presenter
from ui_helpers import RISK_BANDS, VERDICTS

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


def _band_counts(query):
    counts = []
    for band in RISK_BANDS:
        counts.append(query.filter(EmailSubmission.risk_score >= band["lo"],
                                   EmailSubmission.risk_score < band["hi"] + 1).count())
    return counts


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

    band_counts = [{"band": b, "count": n, "pct": _pct(n, total)} for b, n in zip(RISK_BANDS, _band_counts(q))]
    stats = {
        "total": total, "phishing": phishing, "suspicious": suspicious, "legitimate": legitimate,
        "avg_risk": round(q.with_entities(func.avg(EmailSubmission.risk_score)).scalar() or 0.0, 1),
        "high_risk": q.filter(EmailSubmission.risk_score >= RISK_BANDS[2]["lo"]).count(),
        "today": q.filter(EmailSubmission.created_at >= datetime.combine(utcnow().date(), dtime.min)).count(),
        "band_counts": band_counts,
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


def _header(headers, name):
    for key, value in headers.items():
        if key.lower() == name.lower():
            return str(value)[:320]
    return None


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
        has_file = bool(file and file.filename)
        pasted_text = request.form.get("message_text", "")
        has_paste = bool(pasted_text.strip())

        if has_file and has_paste:
            flash("Please use only one input: either paste a message or upload a file.", "danger")
            return redirect(url_for("detector.upload"))
        if not has_file and not has_paste:
            flash("Paste a message or choose a .eml/.txt file to analyse.", "danger")
            return redirect(url_for("detector.upload"))

        if has_file:
            raw_bytes, filename, mimetype = file.read(), file.filename, file.mimetype
        else:
            try:
                raw_bytes, filename, mimetype = pasted.build_from_paste(
                    pasted_text, request.form.get("message_subject", ""), request.form.get("message_sender", ""),
                )
            except pasted.PastedMessageError as exc:
                flash(str(exc), "danger")
                return redirect(url_for("detector.upload"))

        try:
            result = zero_trust.ingest(
                raw_bytes=raw_bytes,
                filename=filename,
                declared_mimetype=mimetype,
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
            original_filename=filename,
            sha256_hash=result.sha256_hash,
            sender=result.sender,
            sender_display_name=scored["header_report"]["display_name"],
            subject=result.subject,
            received_headers_summary=json.dumps(list(result.raw_headers.keys())),
            reply_to=_header(result.raw_headers, "Reply-To"),
            return_path=_header(result.raw_headers, "Return-Path"),
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
    structured_terms = [e for e in explanations if e.get("source") != "text"]
    text_terms = [e for e in explanations if e.get("source") == "text"]
    return render_template(
        "detector/result.html", s=submission,
        structured_terms=structured_terms, text_terms=text_terms,
        view=presenter.build_result_view(submission, structured_terms, text_terms),
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
        "reply_to": submission.reply_to,
        "return_path": submission.return_path,
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


# --------------------------------------------------------------------------
# History, analytics and settings: read-only views over data already stored
# --------------------------------------------------------------------------
HISTORY_PAGE_SIZE = 15
_HISTORY_SORTS = {
    "newest": lambda: EmailSubmission.created_at.desc(),
    "oldest": lambda: EmailSubmission.created_at.asc(),
    "score_desc": lambda: EmailSubmission.risk_score.desc(),
    "score_asc": lambda: EmailSubmission.risk_score.asc(),
}


def _history_filters(query, term, verdict, status):
    if term:
        query = query.filter(or_(
            EmailSubmission.subject.contains(term, autoescape=True),
            EmailSubmission.sender.contains(term, autoescape=True),
            EmailSubmission.original_filename.contains(term, autoescape=True),
        ))
    if verdict in VERDICTS:
        query = query.filter(EmailSubmission.verdict == verdict)
    flagged = EmailSubmission.verdict.in_(FLAGGED_VERDICTS)
    if status == "quarantined":
        query = query.filter(EmailSubmission.quarantined.is_(True))
    elif status == "released":
        query = query.filter(flagged, EmailSubmission.quarantined.is_(False), EmailSubmission.analyst_feedback.is_(None))
    elif status == "pending":
        query = query.filter(flagged, EmailSubmission.analyst_feedback.is_(None))
    elif status in ("confirmed_phish", "false_positive"):
        query = query.filter(EmailSubmission.analyst_feedback == status)
    return query


@detector_bp.route("/history")
@login_required
def history():
    term = request.args.get("q", "").strip()[:100]
    verdict = request.args.get("verdict", "all")
    status = request.args.get("status", "all")
    sort = request.args.get("sort", "newest")
    if sort not in _HISTORY_SORTS:
        sort = "newest"
    query = _history_filters(_visible_query(), term, verdict, status)
    total = query.count()
    pages = max(1, ceil(total / HISTORY_PAGE_SIZE))
    try:
        page = min(max(int(request.args.get("page", 1)), 1), pages)
    except ValueError:
        page = 1
    items = query.order_by(_HISTORY_SORTS[sort]()).offset((page - 1) * HISTORY_PAGE_SIZE).limit(HISTORY_PAGE_SIZE).all()
    active = {k: v for k, v in (("q", term), ("verdict", verdict), ("status", status), ("sort", sort))
              if v and v not in ("all", "newest")}
    return render_template(
        "detector/history.html", items=items, page=page, pages=pages, total=total, args=active,
        term=term, verdict=verdict, status=status, sort=sort,
        has_any=_visible_query().count() > 0,
    )


@detector_bp.route("/analytics")
@login_required
def analytics():
    scope = _visible_query()
    rows = scope.order_by(EmailSubmission.created_at.desc()).limit(2000).all()
    total = len(rows)

    verdict_counts = Counter(r.verdict for r in rows)
    band_counts = Counter(risk_key(r.risk_score) for r in rows)
    histogram = [0] * 10
    for r in rows:
        histogram[min(int((r.risk_score or 0) // 10), 9)] += 1

    today = utcnow().date()
    days = OrderedDict((today - timedelta(days=n), {"total": 0, "flagged": 0}) for n in range(29, -1, -1))
    indicators, brands = Counter(), Counter()
    auth = {m: Counter() for m in ("spf", "dkim", "dmarc")}
    for r in rows:
        bucket = days.get(r.created_at.date())
        if bucket:
            bucket["total"] += 1
            bucket["flagged"] += int(r.verdict in FLAGGED_VERDICTS)
        for raw in r.rule_indicators():
            indicators[indicator_title(raw)] += 1
            code = raw.split(": ", 1)[-1]
            if code.startswith("lookalike_of_"):
                brands[brand_display(code[len("lookalike_of_"):])] += 1
            elif code.startswith("brand_substring_"):
                brands[brand_display(code[len("brand_substring_"):])] += 1
            elif code == "display_name_brand_mismatch":
                brands["Sender-name spoofing"] += 1
        for mech in auth:
            auth[mech][(getattr(r, mech + "_result", None) or "none").lower()] += 1

    domain_query = db.session.query(ExtractedIndicator.value, func.count(func.distinct(ExtractedIndicator.submission_id))) \
        .join(EmailSubmission).filter(ExtractedIndicator.kind == "domain", EmailSubmission.verdict.in_(FLAGGED_VERDICTS))
    if not current_user.is_admin:
        domain_query = domain_query.filter(EmailSubmission.user_id == current_user.id)
    top_domains = domain_query.group_by(ExtractedIndicator.value).order_by(func.count(func.distinct(ExtractedIndicator.submission_id)).desc()).limit(8).all()

    return render_template(
        "detector/analytics.html", total=total, verdict_counts=verdict_counts, band_counts=band_counts,
        histogram=histogram, trend=[{"label": d.strftime("%d %b"), **v} for d, v in days.items()],
        top_indicators=indicators.most_common(8), top_domains=[(defang(d), n) for d, n in top_domains],
        brands=brands.most_common(8),
        auth_failures=[(m.upper(), auth[m]["fail"] + auth[m]["softfail"], sum(v for k, v in auth[m].items() if k != "none"))
                       for m in auth],
        capped=total >= 2000,
    )


def risk_key(score):
    from ui_helpers import risk_band
    return risk_band(score)["key"]


@detector_bp.route("/settings")
@login_required
def settings():
    from analysis.text_model import get_text_model
    model = get_text_model()
    meta = model.meta if model else {}
    return render_template(
        "detector/settings.html",
        submission_count=EmailSubmission.query.filter_by(user_id=current_user.id).count(),
        system={
            "text_model": bool(model), "trained_on": meta.get("trained_on"), "n_train": meta.get("n_train"),
            "virustotal": bool(current_app.config.get("VIRUSTOTAL_API_KEY")),
            "resolver": bool(current_app.config.get("ENABLE_REDIRECT_RESOLVER")),
            "blocklist": len(threat_intel.load_blocklist()),
        },
    )
