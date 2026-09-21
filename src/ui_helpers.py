"""
Presentation helpers shared by every template. No business logic lives here:
this maps stored values (a risk score, a verdict string, a timestamp) onto the
labels, tones and icons the design system renders. The risk-band edges match
the verdict thresholds in analysis/risk_engine.py (30 = suspicious, 60 = phishing).
"""
from datetime import datetime

APP_NAME = "PhishGuard"
APP_TAGLINE = "Advanced Email Threat Detection"
APP_VERSION = "1.0.0"

RISK_BANDS = (
    {"key": "low", "label": "LOW", "lo": 0, "hi": 29, "tone": "success", "icon": "i-shield-check",
     "desc": "Little or no phishing evidence."},
    {"key": "medium", "label": "MEDIUM", "lo": 30, "hi": 59, "tone": "warning", "icon": "i-alert",
     "desc": "Some suspicious signals. Review before trusting."},
    {"key": "high", "label": "HIGH", "lo": 60, "hi": 79, "tone": "danger", "icon": "i-alert-octagon",
     "desc": "Strong phishing indicators. Do not interact."},
    {"key": "critical", "label": "CRITICAL", "lo": 80, "hi": 100, "tone": "critical", "icon": "i-flame",
     "desc": "Overwhelming evidence. Treat as malicious."},
)

VERDICTS = {
    "legitimate": {"label": "SAFE", "tone": "success", "icon": "i-shield-check", "noun": "safe"},
    "suspicious": {"label": "SUSPICIOUS", "tone": "warning", "icon": "i-alert", "noun": "suspicious"},
    "phishing": {"label": "PHISHING", "tone": "danger", "icon": "i-alert-octagon", "noun": "phishing"},
}
_UNKNOWN_VERDICT = {"label": "UNKNOWN", "tone": "neutral", "icon": "i-info", "noun": "unknown"}

SEVERITY = {
    "none": {"label": "NO ISSUES", "tone": "success", "icon": "i-check-circle", "rank": 0},
    "low": {"label": "LOW", "tone": "info", "icon": "i-info", "rank": 1},
    "medium": {"label": "MEDIUM", "tone": "warning", "icon": "i-alert", "rank": 2},
    "high": {"label": "HIGH", "tone": "danger", "icon": "i-alert-octagon", "rank": 3},
    "critical": {"label": "CRITICAL", "tone": "critical", "icon": "i-flame", "rank": 4},
}


def risk_band(score):
    try:
        value = max(0.0, min(100.0, float(score)))
    except (TypeError, ValueError):
        value = 0.0
    for band in RISK_BANDS:
        if value < band["hi"] + 1:
            return band
    return RISK_BANDS[-1]


def verdict_view(verdict):
    return VERDICTS.get(verdict, _UNKNOWN_VERDICT)


def severity_view(level):
    return SEVERITY.get(level, SEVERITY["low"])


def fmt_dt(value, with_time=True):
    if not isinstance(value, datetime):
        return "—"
    return value.strftime("%d %b %Y, %H:%M UTC") if with_time else value.strftime("%d %b %Y")


def fmt_dt_short(value):
    return value.strftime("%d %b %Y, %H:%M") if isinstance(value, datetime) else "—"


def initials(name):
    name = (name or "?").strip()
    return name[:2] if name else "?"


def flash_tone(category):
    return {"success": "success", "danger": "danger", "error": "danger", "warning": "warning"}.get(category, "info")


def flash_icon(category):
    return {"success": "i-check-circle", "danger": "i-x-circle", "error": "i-x-circle", "warning": "i-alert"}.get(category, "i-info")


def event_tone(event_type):
    """Tone for an audit-log event name (presentation only)."""
    name = (event_type or "").lower()
    if any(k in name for k in ("fail", "denied", "rejected", "locked", "refused")):
        return "danger"
    if any(k in name for k in ("quarantine", "role_changed", "threat_intel", "feedback", "upgraded", "released")):
        return "warning"
    if any(k in name for k in ("success", "accepted", "scored", "logout", "register", "2fa")):
        return "success"
    return "info"


def register_ui(app):
    from analysis.explanations import explain_indicator, indicator_title
    app.jinja_env.filters.update(
        event_tone=event_tone, indicator_title=indicator_title, explain_indicator_text=explain_indicator,
        risk_band=risk_band, verdict_view=verdict_view, severity_view=severity_view, dt=fmt_dt,
        initials=initials, dt_short=fmt_dt_short, flash_tone=flash_tone, flash_icon=flash_icon,
    )
    app.jinja_env.globals.update(
        APP_NAME=APP_NAME, APP_TAGLINE=APP_TAGLINE, APP_VERSION=APP_VERSION, RISK_BANDS=RISK_BANDS,
    )

    @app.context_processor
    def _nav_context():
        from flask_login import current_user
        if not (current_user and current_user.is_authenticated):
            return {}
        from models import EmailSubmission
        query = EmailSubmission.query
        if not current_user.is_admin:
            query = query.filter_by(user_id=current_user.id)
        pending = query.filter(
            EmailSubmission.verdict.in_(("phishing", "suspicious")), EmailSubmission.analyst_feedback.is_(None)
        ).count()
        latest = query.order_by(EmailSubmission.created_at.desc()).first()
        return {"nav_pending_review": pending, "nav_last_analysis": latest.created_at if latest else None}
