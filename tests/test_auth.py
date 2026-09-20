import pyotp

from conftest import login
from models import User, AuditLog


def test_register_creates_user_with_hashed_password(client, app):
    resp = client.post("/auth/register", data={
        "username": "newuser", "email": "newuser@example.com",
        "password": "Str0ngPassw0rd!", "confirm_password": "Str0ngPassw0rd!",
        "role": "analyst",
    }, follow_redirects=True)
    assert resp.status_code == 200
    user = User.query.filter_by(username="newuser").first()
    assert user is not None
    assert user.password_hash != "Str0ngPassw0rd!"
    assert user.check_password("Str0ngPassw0rd!")


def test_login_requires_2fa_before_session_established(client, analyst_user):
    resp = client.post("/auth/login", data={
        "username": analyst_user.username, "password": "Str0ngPassw0rd!",
    }, follow_redirects=True)
    # Should be redirected to the 2FA verification step, not the dashboard.
    assert b"Two-factor verification" in resp.data


def test_login_with_wrong_password_fails_and_is_audited(client, analyst_user):
    client.post("/auth/login", data={"username": analyst_user.username, "password": "wrong-password"})
    entries = [e.event_type for e in AuditLog.query.all()]
    assert "login_fail" in entries


def test_full_login_flow_with_valid_totp_succeeds(client, analyst_user):
    resp = login(client, analyst_user)
    assert resp.status_code == 200
    entries = [e.event_type for e in AuditLog.query.all()]
    assert "login_success" in entries


def test_login_with_invalid_totp_code_is_rejected(client, analyst_user):
    client.post("/auth/login", data={"username": analyst_user.username, "password": "Str0ngPassw0rd!"})
    resp = client.post("/auth/verify-2fa", data={"token": "000000"}, follow_redirects=True)
    assert b"Invalid authentication code" in resp.data


def test_account_locks_after_repeated_failed_logins(client, analyst_user):
    for _ in range(5):
        client.post("/auth/login", data={"username": analyst_user.username, "password": "wrong"})
    resp = client.post("/auth/login", data={"username": analyst_user.username, "password": "wrong"}, follow_redirects=True)
    assert b"locked" in resp.data.lower()


def test_analyst_cannot_access_admin_audit_log(client, analyst_user):
    login(client, analyst_user)
    resp = client.get("/admin/audit-log")
    assert resp.status_code == 403
    entries = [e.event_type for e in AuditLog.query.all()]
    assert "role_denied" in entries


def test_admin_can_access_admin_audit_log(client, admin_user):
    login(client, admin_user)
    resp = client.get("/admin/audit-log")
    assert resp.status_code == 200


def test_analyst_cannot_access_user_management(client, analyst_user):
    login(client, analyst_user)
    resp = client.get("/admin/users")
    assert resp.status_code == 403


def test_admin_can_promote_analyst_to_admin(client, admin_user, analyst_user):
    login(client, admin_user)
    resp = client.post(f"/admin/users/{analyst_user.id}/role", data={"role": "admin"}, follow_redirects=True)
    assert resp.status_code == 200
    promoted = User.query.get(analyst_user.id)
    assert promoted.role == "admin"
    entries = [e.event_type for e in AuditLog.query.all()]
    assert "role_changed" in entries


def test_cannot_demote_the_last_remaining_admin(client, admin_user):
    login(client, admin_user)
    resp = client.post(f"/admin/users/{admin_user.id}/role", data={"role": "analyst"}, follow_redirects=True)
    assert resp.status_code == 200
    still_admin = User.query.get(admin_user.id)
    assert still_admin.role == "admin"


def test_can_demote_admin_when_another_admin_remains(client, admin_user, analyst_user):
    login(client, admin_user)
    client.post(f"/admin/users/{analyst_user.id}/role", data={"role": "admin"})  # now two admins
    resp = client.post(f"/admin/users/{analyst_user.id}/role", data={"role": "analyst"}, follow_redirects=True)
    assert resp.status_code == 200
    demoted = User.query.get(analyst_user.id)
    assert demoted.role == "analyst"
