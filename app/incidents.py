"""Incident lifecycle rules (UC-01..UC-07). State pattern as a transition table."""
from flask import g

from . import audit
from .auth import ServiceError
from .db import get_db, transaction

TITLE_MAX, TEXT_MAX = 200, 5000


def clean_text(value, field, max_len):
    """Input validation at the trust boundary (SR-07)."""
    if not isinstance(value, str):
        raise ServiceError(400, f"{field} must be a string")
    value = value.strip()
    if not value:
        raise ServiceError(400, f"{field} is required")
    if len(value) > max_len:
        raise ServiceError(400, f"{field} must be at most {max_len} characters")
    return value


def can_view(user, inc):
    """Need-to-know for sensitive incident data (SR-08). ADMIN and AUDITOR see no incident content."""
    role = user["role"]
    if role == "MANAGER":
        return True
    if role == "ANALYST":
        return inc["assignee_id"] == user["id"] or inc["status"] in ("NEW", "TRIAGED")
    if role == "REPORTER":
        return inc["reporter_id"] == user["id"]
    return False


def _load(db, incident_id):
    inc = db.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    # 404 (not 403) when the user may not see it, so incident IDs can't be enumerated.
    if inc is None or not can_view(g.user, inc):
        raise ServiceError(404, "incident not found")
    return inc


def create(title, description):
    title = clean_text(title, "title", TITLE_MAX)
    description = clean_text(description, "description", TEXT_MAX)
    ts = audit.now()
    with transaction() as db:
        cur = db.execute(
            "INSERT INTO incidents (title, description, reporter_id, created_at, updated_at) VALUES (?,?,?,?,?)",
            (title, description, g.user["id"], ts, ts),
        )
        audit.record(db, g.user["id"], "INCIDENT_REPORTED", f"incident:{cur.lastrowid}")
        return cur.lastrowid


def get(incident_id):
    db = get_db()
    inc = dict(_load(db, incident_id))
    return inc
