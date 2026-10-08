"""Authentication + role-based authorization (SR-01, SR-02, SR-06)."""
import logging

from flask import g
from werkzeug.security import check_password_hash, generate_password_hash

from . import audit
from .db import get_db, transaction

ROLES = {"REPORTER", "ANALYST", "MANAGER", "ADMIN", "AUDITOR"}
MIN_PASSWORD = 12
# Compared against when the username doesn't exist, so response time doesn't reveal valid usernames.
_DUMMY_HASH = generate_password_hash("dummy-password-for-timing")


class ServiceError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def create_user(username, password, role):
    username = (username or "").strip()
    if not (3 <= len(username) <= 32) or not username.replace("_", "").replace(".", "").isalnum():
        raise ServiceError(400, "username must be 3-32 chars: letters, digits, _ or .")
    if role not in ROLES:
        raise ServiceError(400, "invalid role")
    if len(password or "") < MIN_PASSWORD:
        raise ServiceError(400, f"password must be at least {MIN_PASSWORD} characters")
    with transaction() as db:
        if db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
            raise ServiceError(409, "username already exists")
        cur = db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
            (username, generate_password_hash(password), role),
        )
        actor = g.user["id"] if "user" in g else None
        audit.record(db, actor, "USER_CREATED", f"user:{cur.lastrowid}", f"role={role}")
        return cur.lastrowid


def authenticate(username, password):
    with transaction() as db:
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        ok = check_password_hash(user["password_hash"] if user else _DUMMY_HASH, password)
        if user is None or not ok:
            audit.record(db, None, "LOGIN_FAILED", f"username:{username}")
            audit.security_event("LOGIN_FAILED", logging.WARNING, user=username)
            return None
        audit.record(db, user["id"], "LOGIN_OK", f"user:{user['id']}")
        audit.security_event("LOGIN_OK", user=username)
        return user
