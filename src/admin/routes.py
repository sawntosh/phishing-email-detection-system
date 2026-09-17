import json
import os

from flask import Blueprint, render_template, current_app
from flask_login import login_required

from models import AuditLog, EmailSubmission
from security_utils import admin_required

admin_bp = Blueprint("admin", __name__, template_folder="../templates/admin")


@admin_bp.route("/audit-log")
@login_required
@admin_required
def audit_log():
    entries = AuditLog.query.order_by(AuditLog.id.desc()).limit(300).all()
    is_valid, broken_id = AuditLog.verify_chain()
    return render_template("admin/audit_log.html", entries=entries, is_valid=is_valid, broken_id=broken_id)


@admin_bp.route("/model-performance")
@login_required
@admin_required
def model_performance():
    report_path = os.path.join(current_app.instance_path, "model_eval_report.json")
    eval_report = None
    if os.path.exists(report_path):
        with open(report_path) as f:
            eval_report = json.load(f)

    fp_count = EmailSubmission.query.filter_by(analyst_feedback="false_positive").count()
    confirmed_count = EmailSubmission.query.filter_by(analyst_feedback="confirmed_phish").count()
    total_scored = EmailSubmission.query.count()

    return render_template(
        "admin/model_performance.html", eval_report=eval_report,
        fp_count=fp_count, confirmed_count=confirmed_count, total_scored=total_scored,
    )
