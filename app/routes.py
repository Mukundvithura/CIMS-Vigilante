"""HTTP layer only: parse input, call a service, return JSON. Business rules live in the services."""

from flask import Blueprint, g, jsonify, request, session

from . import auth, evidence, incidents
from .auth import ServiceError, role_required

bp = Blueprint("api", __name__)
STAFF = ("ANALYST", "MANAGER")


def body():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ServiceError(400, "JSON object body required")
    return data


@bp.get("/me")
@role_required()
def me():
    return {"id": g.user["id"], "username": g.user["username"], "role": g.user["role"]}


@bp.post("/login")
def login():
    data = body()
    username, password = data.get("username"), data.get("password")
    if not isinstance(username, str) or not isinstance(password, str) or len(username) > 32 or len(password) > 128:
        raise ServiceError(400, "username and password required")
    user = auth.authenticate(username, password)
    if user is None:
        raise ServiceError(401, "invalid credentials")  # same message for wrong user / wrong password / locked
    session.clear()  # new session on login (session fixation)
    session.permanent = True  # applies PERMANENT_SESSION_LIFETIME (30 min timeout, SR-04)
    session["uid"] = user["id"]
    return {"id": user["id"], "role": user["role"]}


@bp.post("/logout")
def logout():
    session.clear()
    return {"status": "logged out"}


@bp.get("/incidents")
@role_required("REPORTER", *STAFF)
def list_incidents():
    return jsonify(incidents.list_visible())


@bp.post("/incidents")
@role_required("REPORTER", *STAFF)
def report_incident():
    data = body()
    return {"id": incidents.create(data.get("title"), data.get("description"))}, 201


@bp.get("/incidents/<int:incident_id>")
@role_required("REPORTER", *STAFF)
def get_incident(incident_id):
    return incidents.get(incident_id)


@bp.post("/incidents/<int:incident_id>/classify")
@role_required(*STAFF)
def classify(incident_id):
    incidents.classify(incident_id, body().get("severity"))
    return {"status": "TRIAGED"}


@bp.post("/incidents/<int:incident_id>/assign")
@role_required("MANAGER")
def assign(incident_id):
    assignee = body().get("assignee_id")
    if not isinstance(assignee, int):
        raise ServiceError(400, "assignee_id must be an integer")
    incidents.assign(incident_id, assignee)
    return {"status": "ASSIGNED"}


@bp.post("/incidents/<int:incident_id>/status")
@role_required(*STAFF)
def update_status(incident_id):
    data = body()
    incidents.update_status(incident_id, data.get("status"), data.get("reason"))
    return {"status": data.get("status")}


@bp.post("/incidents/<int:incident_id>/notes")
@role_required(*STAFF)
def add_note(incident_id):
    return {"id": incidents.add_note(incident_id, body().get("note"))}, 201


@bp.post("/incidents/<int:incident_id>/evidence")
@role_required(*STAFF)
def add_evidence(incident_id):
    evidence_id, digest = evidence.add(incident_id, request.files.get("file"))
    return {"id": evidence_id, "sha256": digest}, 201
