"""
User-facing error pages. Users only ever see a friendly message and an error
reference; stack traces, SQL, file paths and secrets go to the server log
(see logging_config.py), never to the browser.
"""
import logging

from flask import g, render_template, request
from flask_login import current_user
from werkzeug.exceptions import HTTPException

from logging_config import security_log

_MESSAGES = {
    400: ("Bad request", "The request could not be understood. Please check what you entered and try again."),
    401: ("Sign in required", "Please sign in to continue."),
    405: ("Method not allowed", "That action is not supported for this page."),
    413: ("Upload too large", "The message or file you submitted is larger than the 5 MB limit."),
    429: ("Too many requests", "You have made too many requests in a short time. Please wait a while and try again."),
    500: ("Something went wrong", "An unexpected error occurred. It has been logged; please try again."),
}


def _reference():
    return getattr(g, "request_id", None)


def _render_generic(code, title, message):
    return render_template("errors/generic.html", code=code, title=title, message=message, reference=_reference()), code


def _user_id():
    return current_user.get_id() if current_user and current_user.is_authenticated else None


def register_error_handlers(app):
    @app.errorhandler(HTTPException)
    def handle_http_exception(exc):
        code = exc.code or 500
        if code == 403:
            security_log("access_denied", user_id=_user_id(), method=request.method, path=request.path)
            return render_template("errors/403.html", reference=_reference()), 403
        if code == 404:
            return render_template("errors/404.html", reference=_reference()), 404
        if code in (401, 429):
            security_log("request_refused", status=code, user_id=_user_id(), method=request.method, path=request.path)
        title, message = _MESSAGES.get(code, ("Request could not be completed", "Please try again."))
        return _render_generic(code, title, message)

    @app.errorhandler(Exception)
    def handle_unexpected_exception(exc):
        # In tests and in explicit debug mode let the exception surface so it can be diagnosed;
        # PROPAGATE_EXCEPTIONS=False forces the production behaviour (used by the error-page tests).
        if (app.testing or app.debug) and app.config.get("PROPAGATE_EXCEPTIONS") is not False:
            raise exc
        logging.getLogger("phishdetect").error(
            "unhandled_exception", exc_info=exc,
            extra={"fields": {"method": request.method, "path": request.path, "user_id": _user_id()}},
        )
        title, message = _MESSAGES[500]
        return _render_generic(500, title, message)
