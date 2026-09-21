import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, ROOT)

import pytest
import pyotp

from config import Config
from app import create_app
from models import db, User


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    RATELIMIT_ENABLED = False


@pytest.fixture(scope="session", autouse=True)
def _ensure_model_trained():
    """Train small synthetic models once for the whole test session if they
    don't already exist (`python train_model.py`, run separately, produces the
    full real-corpus models used by the running app)."""
    from analysis.ml_classifier import MODEL_PATH
    from analysis.text_model import TEXT_MODEL_PATH
    if not (os.path.exists(MODEL_PATH) and os.path.exists(TEXT_MODEL_PATH)):
        import importlib
        train_model = importlib.import_module("train_model")
        train_model.main(["--source", "synthetic"])
    yield


@pytest.fixture(autouse=True)
def _isolated_blocklist(tmp_path, monkeypatch):
    """Never let a developer's real instance/threat_intel/blocklist.txt change test results."""
    monkeypatch.setenv("THREAT_BLOCKLIST_PATH", str(tmp_path / "no_blocklist.txt"))


@pytest.fixture
def app(monkeypatch):
    # Tests must not depend on the developer's local .env: if
    # DEFAULT_ADMIN_PASSWORD happens to be set there, create_app() would
    # silently seed an extra admin account into every test's database,
    # breaking any test that reasons about "the only admin" (e.g. the
    # last-admin-cannot-be-demoted safeguard). Set (not delete) the var:
    # create_app() calls load_dotenv() internally, which only fills in
    # variables that are *absent* from os.environ -- deleting it would
    # just let .env repopulate it right back.
    monkeypatch.setenv("DEFAULT_ADMIN_PASSWORD", "")

    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def make_user(username="analyst1", role="analyst", password="Str0ngPassw0rd!", enable_2fa=True):
    user = User(
        username=username, email=f"{username}@example.com", role=role,
        totp_secret=pyotp.random_base32(), totp_enabled=enable_2fa,
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def analyst_user(app):
    return make_user("analyst1", "analyst")


@pytest.fixture
def admin_user(app):
    return make_user("admin1", "admin")


def login(client, user, password="Str0ngPassw0rd!"):
    client.post("/auth/login", data={"username": user.username, "password": password}, follow_redirects=True)
    code = pyotp.TOTP(user.totp_secret).now()
    return client.post("/auth/verify-2fa", data={"token": code}, follow_redirects=True)
