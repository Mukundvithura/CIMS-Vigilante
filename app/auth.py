"""Authentication + role-based authorization (SR-01, SR-02, SR-06)."""
import logging
from functools import wraps

from flask import abort, g, session
from werkzeug.security import check_password_hash, generate_password_hash

from . import audit
from .db import get_db, transaction

ROLES = {"REPORTER", "ANALYST", "MANAGER", "ADMIN", "AUDITOR"}
MAX_FAILED = 5
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
        if user is None or user["locked"] or not ok:
            if user is not None and not user["locked"]:
                fails = user["failed_logins"] + 1
                locked = int(fails >= MAX_FAILED)
                db.execute("UPDATE users SET failed_logins = ?, locked = ? WHERE id = ?", (fails, locked, user["id"]))
                if locked:
                    audit.record(db, None, "ACCOUNT_LOCKED", f"user:{user['id']}")
                    audit.security_event("ACCOUNT_LOCKED", logging.WARNING, user=username)
            audit.record(db, None, "LOGIN_FAILED", f"username:{username}")
            audit.security_event("LOGIN_FAILED", logging.WARNING, user=username)
            return None
        db.execute("UPDATE users SET failed_logins = 0 WHERE id = ?", (user["id"],))
        audit.record(db, user["id"], "LOGIN_OK", f"user:{user['id']}")
        audit.security_event("LOGIN_OK", user=username)
        return user


def role_required(*roles):
    """Loads the user from the DB on every request, so a role change or lock applies immediately."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            uid = session.get("uid")
            user = uid and get_db().execute("SELECT id, username, role, locked FROM users WHERE id = ?", (uid,)).fetchone()
            if not user or user["locked"]:
                session.clear()
                abort(401)
            if roles and user["role"] not in roles:
                with transaction() as db:
                    audit.record(db, user["id"], "ACCESS_DENIED", fn.__name__, f"role={user['role']}")
                audit.security_event("ACCESS_DENIED", logging.WARNING, user=user["username"], endpoint=fn.__name__)
                abort(403)
            g.user = user
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def change_role(user_id, new_role):
    """Privilege-escalation guard (SR-06): only ADMIN, never on their own account."""
    if new_role not in ROLES:
        raise ServiceError(400, "invalid role")
    if user_id == g.user["id"]:
        raise ServiceError(403, "administrators cannot change their own role")
    with transaction() as db:
        target = db.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()
        if target is None:
            raise ServiceError(404, "user not found")
        db.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
        audit.record(db, g.user["id"], "ROLE_CHANGED", f"user:{user_id}", f"{target['role']}->{new_role}")
    audit.security_event("ROLE_CHANGED", logging.WARNING, by=g.user["username"], target=user_id, role=new_role)


def unlock_user(user_id):
    with transaction() as db:
        if db.execute("UPDATE users SET locked = 0, failed_logins = 0 WHERE id = ?", (user_id,)).rowcount == 0:
            raise ServiceError(404, "user not found")
        audit.record(db, g.user["id"], "ACCOUNT_UNLOCKED", f"user:{user_id}")
