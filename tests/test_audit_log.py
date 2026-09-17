from models import db, AuditLog


def test_chain_is_valid_after_normal_appends(app):
    AuditLog.append("login_success", user_id=1, username="alice", detail="ok")
    AuditLog.append("ingest_accepted", user_id=1, username="alice", detail="sha256=abc")
    AuditLog.append("scored", user_id=1, username="alice", detail="verdict=phishing")
    is_valid, broken_id = AuditLog.verify_chain()
    assert is_valid is True
    assert broken_id is None


def test_chain_detects_tampering_with_historical_entry(app):
    AuditLog.append("login_success", user_id=1, username="alice", detail="ok")
    entry = AuditLog.append("ingest_accepted", user_id=1, username="alice", detail="sha256=abc")
    AuditLog.append("scored", user_id=1, username="alice", detail="verdict=phishing")

    # Simulate an attacker editing history directly in the database.
    entry.detail = "sha256=tampered"
    db.session.commit()

    is_valid, broken_id = AuditLog.verify_chain()
    assert is_valid is False
    assert broken_id == entry.id
