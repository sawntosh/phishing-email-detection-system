import json
import os

from flask import Blueprint, render_template, current_app, request, redirect, url_for, flash, abort
from flask_login import login_required, current_user

from models import db, AuditLog, EmailSubmission, User, utcnow
from security_utils import admin_required

admin_bp = Blueprint("admin", __name__, template_folder="../templates/admin")


def _client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr)


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


@admin_bp.route("/users")
@login_required
@admin_required
def users():
    all_users = User.query.order_by(User.created_at.asc()).all()
    return render_template("admin/users.html", users=all_users, now=utcnow())


@admin_bp.route("/users/<int:user_id>/role", methods=["POST"])
@login_required
@admin_required
def change_user_role(user_id):
    target = User.query.get_or_404(user_id)
    new_role = request.form.get("role")
    if new_role not in ("analyst", "admin"):
        abort(400)

    old_role = target.role
    if old_role == new_role:
        flash("No change: user already has that role.", "warning")
        return redirect(url_for("admin.users"))

    # Availability safeguard: never allow the last remaining admin to be
    # demoted -- by themselves or another admin -- which would leave the
    # system with no one able to manage roles, view the audit log, or
    # promote anyone back. This is the real invariant that matters (not a
    # blanket "can't touch your own row" rule, which would make this
    # safeguard unreachable whenever there's exactly one admin).
    if old_role == "admin" and new_role == "analyst":
        remaining_admins = User.query.filter_by(role="admin").count()
        if remaining_admins <= 1:
            flash("Cannot demote the last remaining admin account.", "danger")
            return redirect(url_for("admin.users"))

    target.role = new_role
    db.session.commit()
    AuditLog.append(
        "role_changed", user_id=current_user.id, username=current_user.username,
        ip_address=_client_ip(),
        detail=f"target_user_id={target.id} target_username={target.username} {old_role}->{new_role}",
    )
    flash(f"{target.username}'s role changed to {new_role}.", "success")
    return redirect(url_for("admin.users"))
