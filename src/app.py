import os

import pyotp
from flasgger import Swagger
from flask import Flask, render_template, request
from flask_login import LoginManager
from dotenv import load_dotenv
from sqlalchemy import inspect, text

from config import BASE_DIR, Config
from error_handlers import register_error_handlers
from logging_config import configure_logging, register_request_logging
from models import db, User
from security_utils import csrf
from ui_helpers import register_ui

login_manager = LoginManager()
login_manager.login_view = "auth.login"


def create_app(config_class=Config):
    load_dotenv()
    # Pin the instance folder to <project>/instance, where the database, trained models, evaluation
    # reports and logs live. Flask's default would be src/instance, a different (empty) folder.
    app = Flask(__name__, instance_path=os.path.join(BASE_DIR, "instance"), instance_relative_config=True)
    app.config.from_object(config_class)
    os.makedirs(app.instance_path, exist_ok=True)

    # Swagger UI for manually exercising the routes below -- see /apidocs.
    # Documentation only; it does not change auth/CSRF, so POST routes still
    # need an active logged-in session (and a CSRF token where required),
    # same as using the app in a browser.
    app.config["SWAGGER"] = {
        "title": "Phishing Email Detection API",
        "description": "Endpoints for the phishing detector. Log in via the web UI first, "
                        "in the same browser tab as /apidocs, so requests carry your session cookie.",
        "uiversion": 3,
        "specs_route": "/apidocs/",
    }
    Swagger(app)

    configure_logging(app)
    register_request_logging(app)
    register_error_handlers(app)
    register_ui(app)

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
        if request.blueprint == "flasgger":
            # Swagger UI (the /apidocs page only) needs an inline <script> to boot
            # itself and loads its font from Google Fonts; the strict policy below
            # blocks both silently, which just looks like the page hanging on the
            # loading spinner forever. Relaxed here, and only here -- every other
            # route in the app keeps the strict policy.
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:"
            )
        else:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"
            )
        if app.config.get("SESSION_COOKIE_SECURE"):
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    from analysis.explanations import explain_indicator, defang
    app.jinja_env.filters["explain_indicator"] = explain_indicator
    app.jinja_env.filters["defang"] = defang

    with app.app_context():
        db.create_all()
        _add_missing_columns()
        _ensure_default_admin(app)

    return app


def _add_missing_columns():
    """db.create_all() never alters an existing table. Add any nullable columns
    introduced after a database file was first created so upgrading needs no
    manual migration (SQLite ALTER TABLE ... ADD COLUMN)."""
    inspector = inspect(db.engine)
    for table in db.metadata.sorted_tables:
        if not inspector.has_table(table.name):
            continue
        existing = {c["name"] for c in inspector.get_columns(table.name)}
        for column in table.columns:
            if column.name in existing or not column.nullable or column.primary_key:
                continue
            ddl = column.type.compile(dialect=db.engine.dialect)
            db.session.execute(text(f'ALTER TABLE "{table.name}" ADD COLUMN "{column.name}" {ddl}'))
            db.session.commit()


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
    # Werkzeug's interactive debugger can execute code and shows stack traces, so it is opt-in
    # (FLASK_DEBUG=true in .env) and can never be enabled when FLASK_ENV=production.
    debug_requested = os.environ.get("FLASK_DEBUG", "").strip().lower() in ("1", "true", "yes", "on")
    application.run(debug=debug_requested and os.environ.get("FLASK_ENV") != "production")
