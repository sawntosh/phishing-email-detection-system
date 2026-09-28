from datetime import timedelta

import pyotp
import qrcode
import qrcode.image.svg
import io
import base64
from flask import Blueprint, render_template, redirect, url_for, flash, request, session, jsonify
from flask_login import login_user, logout_user, login_required, current_user

from models import db, User, AuditLog, utcnow
from security_utils import limiter, csrf
from auth.forms import RegisterForm, LoginForm, TwoFactorForm

auth_bp = Blueprint("auth", __name__, template_folder="../templates/auth")

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


def _client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr)


@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("20 per hour")
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter((User.username == form.username.data) | (User.email == form.email.data)).first():
            flash("Username or email already registered.", "danger")
            return render_template("auth/register.html", form=form)

        user = User(
            username=form.username.data.strip(),
            email=form.email.data.strip().lower(),
            role="analyst",
            totp_secret=pyotp.random_base32(),
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        AuditLog.append("user_registered", user_id=user.id, username=user.username, ip_address=_client_ip())

        session["setup_2fa_user_id"] = user.id
        flash("Account created. Please set up two-factor authentication to continue.", "success")
        return redirect(url_for("auth.setup_2fa"))
    return render_template("auth/register.html", form=form)


@auth_bp.route("/setup-2fa")
def setup_2fa():
    user_id = session.get("setup_2fa_user_id")
    if not user_id:
        return redirect(url_for("auth.login"))
    user = User.query.get_or_404(user_id)
    totp_uri = pyotp.totp.TOTP(user.totp_secret).provisioning_uri(
        name=user.email, issuer_name="Explainable Phishing Detector"
    )
    factory = qrcode.image.svg.SvgImage
    img = qrcode.make(totp_uri, image_factory=factory)
    buf = io.BytesIO()
    img.save(buf)
    qr_svg_b64 = base64.b64encode(buf.getvalue()).decode()
    return render_template("auth/setup_2fa.html", qr_svg_b64=qr_svg_b64, secret=user.totp_secret, form=TwoFactorForm())


@auth_bp.route("/confirm-2fa-setup", methods=["POST"])
def confirm_2fa_setup():
    user_id = session.get("setup_2fa_user_id")
    if not user_id:
        return redirect(url_for("auth.login"))
    user = User.query.get_or_404(user_id)
    form = TwoFactorForm()
    if form.validate_on_submit() and pyotp.TOTP(user.totp_secret).verify(form.token.data, valid_window=1):
        user.totp_enabled = True
        db.session.commit()
        session.pop("setup_2fa_user_id", None)
        AuditLog.append("2fa_enabled", user_id=user.id, username=user.username, ip_address=_client_ip())
        flash("Two-factor authentication enabled. You can now log in.", "success")
        return redirect(url_for("auth.login"))
    flash("Invalid code, please try again.", "danger")
    return redirect(url_for("auth.setup_2fa"))


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("20 per hour")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data.strip()).first()

        if user and user.locked_until and user.locked_until > utcnow():
            AuditLog.append("login_fail_locked", user_id=user.id, username=user.username, ip_address=_client_ip())
            flash("Account temporarily locked due to repeated failed attempts. Try again later.", "danger")
            return render_template("auth/login.html", form=form)

        hash_before = user.password_hash if user else None
        if user and user.check_password(form.password.data):
            user.failed_login_count = 0
            user.locked_until = None
            db.session.commit()
            if user.password_hash != hash_before:
                AuditLog.append("password_hash_upgraded", user_id=user.id, username=user.username,
                                ip_address=_client_ip(), detail="legacy or outdated hash replaced with Argon2id")
            if not user.totp_enabled:
                session["setup_2fa_user_id"] = user.id
                flash("Please finish setting up two-factor authentication.", "warning")
                return redirect(url_for("auth.setup_2fa"))
            session["pending_2fa_user_id"] = user.id
            return redirect(url_for("auth.verify_2fa"))

        if user:
            user.failed_login_count = (user.failed_login_count or 0) + 1
            if user.failed_login_count >= MAX_FAILED_ATTEMPTS:
                user.locked_until = utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
            db.session.commit()

        AuditLog.append("login_fail", username=form.username.data.strip(), ip_address=_client_ip())
        flash("Invalid username or password.", "danger")
    return render_template("auth/login.html", form=form)


@auth_bp.route("/verify-2fa", methods=["GET", "POST"])
@limiter.limit("20 per hour")
def verify_2fa():
    user_id = session.get("pending_2fa_user_id")
    if not user_id:
        return redirect(url_for("auth.login"))
    user = User.query.get_or_404(user_id)
    form = TwoFactorForm()
    if form.validate_on_submit():
        if pyotp.TOTP(user.totp_secret).verify(form.token.data, valid_window=1):
            session.pop("pending_2fa_user_id", None)
            login_user(user)
            session.permanent = True  # enforces PERMANENT_SESSION_LIFETIME (30-min idle timeout)
            user.last_login_at = utcnow()
            db.session.commit()
            AuditLog.append("login_success", user_id=user.id, username=user.username, ip_address=_client_ip())
            return redirect(url_for("detector.dashboard"))
        AuditLog.append("2fa_fail", user_id=user.id, username=user.username, ip_address=_client_ip())
        flash("Invalid authentication code.", "danger")
    return render_template("auth/verify_2fa.html", form=form)


@auth_bp.route("/api-token", methods=["POST"])
@limiter.limit("10 per hour")
@csrf.exempt
def issue_api_token():
    """
    Exchange username + password + current TOTP code for a bearer token,
    used by POST /api/analyze (the endpoint Swagger's "Try it out" needs).
    Same password/lockout checks as the normal login form, plus 2FA -- this
    is a machine-facing alternative to session-cookie login, not a way
    around it. CSRF-exempt because it authenticates via a request body, not
    an ambient session cookie, so CSRF (a forged request riding a victim's
    cookies) does not apply.
    ---
    tags: [auth]
    consumes:
      - application/json
    parameters:
      - in: body
        name: credentials
        required: true
        schema:
          type: object
          required: [username, password, totp_code]
          properties:
            username: {type: string}
            password: {type: string}
            totp_code: {type: string, description: "6-digit code from your authenticator app"}
    responses:
      200:
        description: '{"api_token": "..."} -- shown once, store it now; issuing a new token invalidates the old one.'
      401:
        description: Invalid username/password/code, 2FA not set up yet, or account locked.
    """
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    totp_code = (data.get("totp_code") or "").strip()

    user = User.query.filter_by(username=username).first()

    if user and user.locked_until and user.locked_until > utcnow():
        AuditLog.append("login_fail_locked", user_id=user.id, username=user.username,
                         ip_address=_client_ip(), detail="api-token")
        return jsonify(error="Account temporarily locked due to repeated failed attempts."), 401

    if user and user.check_password(password):
        if not user.totp_enabled:
            return jsonify(error="Finish two-factor authentication setup via the web UI first."), 401
        if pyotp.TOTP(user.totp_secret).verify(totp_code, valid_window=1):
            user.failed_login_count = 0
            user.locked_until = None
            token = user.set_api_token()
            db.session.commit()
            AuditLog.append("api_token_issued", user_id=user.id, username=user.username, ip_address=_client_ip())
            return jsonify(api_token=token)
        AuditLog.append("2fa_fail", user_id=user.id, username=user.username,
                         ip_address=_client_ip(), detail="api-token")
        return jsonify(error="Invalid authentication code."), 401

    if user:
        user.failed_login_count = (user.failed_login_count or 0) + 1
        if user.failed_login_count >= MAX_FAILED_ATTEMPTS:
            user.locked_until = utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
        db.session.commit()

    AuditLog.append("login_fail", username=username, ip_address=_client_ip(), detail="api-token")
    return jsonify(error="Invalid username or password."), 401


@auth_bp.route("/logout")
@login_required
def logout():
    AuditLog.append("logout", user_id=current_user.id, username=current_user.username, ip_address=_client_ip())
    logout_user()
    session.clear()  # invalidate the whole session, not just the Flask-Login keys
    return redirect(url_for("auth.login"))
