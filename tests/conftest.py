import functools

import pytest
from werkzeug.security import generate_password_hash

from app import auth, create_app
from app.auth import create_user

# Tests only: cheap hashing so the suite runs in seconds. Production keeps werkzeug's default (scrypt).
auth.generate_password_hash = functools.partial(generate_password_hash, method="pbkdf2:sha256:1000")

PW = "correct-horse-battery"
USERS = {
    "reporter": "REPORTER", "reporter2": "REPORTER",
    "analyst": "ANALYST", "analyst2": "ANALYST",
    "manager": "MANAGER", "admin": "ADMIN", "auditor": "AUDITOR",
}
ORDER = ["NEW", "TRIAGED", "ASSIGNED", "INVESTIGATING", "RESOLVED", "CLOSED"]


@pytest.fixture
def app(tmp_path):
    app = create_app({
        "SECRET_KEY": "k" * 40,
        "DATABASE": str(tmp_path / "test.db"),
        "EVIDENCE_DIR": str(tmp_path / "evidence"),
        "SESSION_COOKIE_SECURE": False,
        "TESTING": True,
    })
    with app.app_context():
        app.ids = {name: create_user(name, PW, role) for name, role in USERS.items()}
    return app


@pytest.fixture
def login(app):
    """login("analyst") -> a test client holding that user's session."""
    def _login(name):
        client = app.test_client()
        r = client.post("/login", json={"username": name, "password": PW})
        assert r.status_code == 200, r.json
        return client
    return _login


@pytest.fixture
def incident(app, login):
    """incident("RESOLVED") -> id of an incident walked through the real API up to that status."""
    def _incident(upto="NEW", severity="HIGH"):
        rep, mgr, ana = login("reporter"), login("manager"), login("analyst")
        iid = rep.post("/incidents", json={"title": "Phishing email", "description": "Macro attachment"}).json["id"]
        steps = [
            ("TRIAGED", mgr, f"/incidents/{iid}/classify", {"severity": severity}),
            ("ASSIGNED", mgr, f"/incidents/{iid}/assign", {"assignee_id": app.ids["analyst"]}),
            ("INVESTIGATING", ana, f"/incidents/{iid}/status", {"status": "INVESTIGATING"}),
            ("RESOLVED", ana, f"/incidents/{iid}/status", {"status": "RESOLVED"}),
            ("CLOSED", mgr, f"/incidents/{iid}/status", {"status": "CLOSED", "reason": "contained"}),
        ]
        for status, client, url, body in steps:
            if ORDER.index(status) > ORDER.index(upto):
                break
            r = client.post(url, json=body)
            assert r.status_code == 200, r.json
        return iid
    return _incident
