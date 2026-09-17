import os

import pyotp
from flask import Flask, render_template
from flask_login import LoginManager
from flask_wtf import CSRFProtect
from dotenv import load_dotenv

from config import Config
from models import db, User

csrf = CSRFProtect()
login_manager = LoginManager()
login_manager.login_view = "auth.login"


def create_app(config_class=Config):
    load_dotenv()
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_class)
    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)

    from security_utils import limiter
    limiter.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    from auth.routes import auth_bp
    from detector.routes import detector_bp
    from admin.routes import admin_bp

    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(detector_bp, url_prefix="/")
    app.register_blueprint(admin_bp, url_prefix="/admin")

    @app.after_request
    def set_security_headers(response):
        # Section A05 (Security Misconfiguration) mitigations
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"
        )
        if app.config.get("SESSION_COOKIE_SECURE"):
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("errors/404.html"), 404

    with app.app_context():
        db.create_all()
        _ensure_default_admin(app)

    return app


def _ensure_default_admin(app):
    """Creates a default admin on first run ONLY from environment
    variables (never a hard-coded password) so the app is usable out of
    the box for marking/demo without ever shipping a real credential."""
    if User.query.filter_by(role="admin").first():
        return
    default_password = os.environ.get("DEFAULT_ADMIN_PASSWORD")
    if not default_password:
        app.logger.warning(
            "No admin account exists and DEFAULT_ADMIN_PASSWORD is not set in .env — "
            "register the first user via /auth/register instead."
        )
        return
    admin = User(
        username=os.environ.get("DEFAULT_ADMIN_USERNAME", "admin"),
        email=os.environ.get("DEFAULT_ADMIN_EMAIL", "admin@example.com"),
        role="admin",
        totp_secret=pyotp.random_base32(),
    )
    admin.set_password(default_password)
    db.session.add(admin)
    db.session.commit()
    app.logger.info("Default admin account created from .env; complete 2FA setup at /auth/setup-2fa on first login.")


if __name__ == "__main__":
    application = create_app()
    application.run(debug=os.environ.get("FLASK_ENV") != "production")
