"""RBAC decorators + shared security extensions (rate limiter, CSRF)."""
from functools import wraps

from flask import abort
from flask_login import current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect

limiter = Limiter(key_func=get_remote_address)
# Defined here (not in app.py) so every module references the SAME instance
# regardless of whether app.py is imported normally or run directly as
# `python app.py` (which Python loads as __main__, not as a module named
# "app" -- a second `from app import csrf` elsewhere would then re-execute
# app.py and silently create a second, uninitialised CSRFProtect object).
csrf = CSRFProtect()


def roles_required(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            if current_user.role not in roles:
                from models import AuditLog
                AuditLog.append(
                    "role_denied", user_id=current_user.id, username=current_user.username,
                    detail=f"required one of {roles}, had '{current_user.role}'",
                )
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator


admin_required = roles_required("admin")
analyst_or_admin_required = roles_required("analyst", "admin")
