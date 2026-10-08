"""Incident lifecycle rules (UC-01..UC-07). State pattern as a transition table."""
from flask import g

from . import audit
from .auth import ServiceError
from .db import get_db, transaction

SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
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


def require_workable(db, incident_id):
    """Only the assigned analyst or a manager may add notes/evidence, and never on a CLOSED incident."""
    inc = _load(db, incident_id)
    if inc["status"] == "CLOSED":
        raise ServiceError(409, "closed incidents are read-only")
    if not (g.user["role"] == "MANAGER" or (g.user["role"] == "ANALYST" and inc["assignee_id"] == g.user["id"])):
        raise ServiceError(403, "only the assigned analyst or a manager can do this")
    if inc["status"] in ("NEW", "TRIAGED"):
        raise ServiceError(409, "incident must be assigned first")
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
    inc["notes"] = [dict(r) for r in db.execute(
        "SELECT id, author_id, note, created_at FROM notes WHERE incident_id = ? ORDER BY id", (incident_id,))]
    return inc


def classify(incident_id, severity):
    if severity not in SEVERITIES:
        raise ServiceError(400, "severity must be one of LOW, MEDIUM, HIGH, CRITICAL")
    with transaction() as db:
        inc = _load(db, incident_id)
        if inc["status"] not in ("NEW", "TRIAGED"):
            raise ServiceError(409, "severity can only be set before assignment")
        db.execute("UPDATE incidents SET severity = ?, status = 'TRIAGED', updated_at = ? WHERE id = ?",
                   (severity, audit.now(), incident_id))
        audit.record(db, g.user["id"], "SEVERITY_SET", f"incident:{incident_id}", f"{inc['severity']}->{severity}")


def assign(incident_id, assignee_id):
    with transaction() as db:
        inc = _load(db, incident_id)
        if inc["status"] not in ("TRIAGED", "ASSIGNED"):
            raise ServiceError(409, "incident must be triaged before assignment")
        analyst = db.execute("SELECT id FROM users WHERE id = ? AND role = 'ANALYST' AND locked = 0", (assignee_id,)).fetchone()
        if analyst is None:
            raise ServiceError(400, "assignee must be an active analyst")
        db.execute("UPDATE incidents SET assignee_id = ?, status = 'ASSIGNED', updated_at = ? WHERE id = ?",
                   (assignee_id, audit.now(), incident_id))
        audit.record(db, g.user["id"], "INCIDENT_ASSIGNED", f"incident:{incident_id}",
                     f"{inc['assignee_id']}->{assignee_id}")


def add_note(incident_id, note):
    note = clean_text(note, "note", TEXT_MAX)
    with transaction() as db:
        require_workable(db, incident_id)
        cur = db.execute("INSERT INTO notes (incident_id, author_id, note, created_at) VALUES (?,?,?,?)",
                         (incident_id, g.user["id"], note, audit.now()))
        audit.record(db, g.user["id"], "NOTE_ADDED", f"incident:{incident_id}", f"note:{cur.lastrowid}")
        return cur.lastrowid
