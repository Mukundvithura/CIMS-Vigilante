"""Incident lifecycle rules (UC-01..UC-07). State pattern as a transition table."""
from flask import g

from .auth import ServiceError
from .db import get_db


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


def get(incident_id):
    db = get_db()
    inc = dict(_load(db, incident_id))
    return inc
