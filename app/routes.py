"""HTTP layer only: parse input, call a service, return JSON. Business rules live in the services."""

from flask import Blueprint, g, request, session

from . import auth, incidents
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
    if not username or not password:
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


@bp.post("/incidents")
@role_required("REPORTER", *STAFF)
def report_incident():
    data = body()
    return {"id": incidents.create(data.get("title"), data.get("description"))}, 201


@bp.get("/incidents/<int:incident_id>")
@role_required("REPORTER", *STAFF)
def get_incident(incident_id):
    return incidents.get(incident_id)
