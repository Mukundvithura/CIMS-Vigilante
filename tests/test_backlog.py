"""One test per Jira story (project EN). Each test checks that story's acceptance criteria through the real API."""
import hashlib
import io
import sqlite3
import time
from pathlib import Path

import pytest

from app import audit, create_app
from app.db import get_db, transaction
from conftest import PW


def upload(client, iid, data, name):
    return client.post(f"/incidents/{iid}/evidence", data={"file": (io.BytesIO(data), name)},
                       content_type="multipart/form-data")


# EN-7 SR-01 Log in with username and password
def test_en7_login(app):
    c = app.test_client()
    r = c.post("/login", json={"username": "analyst", "password": PW})
    assert r.status_code == 200 and r.json["role"] == "ANALYST"
    cookie = r.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
    wrong_pw = c.post("/login", json={"username": "analyst", "password": "nope-nope-nope"})
    no_user = c.post("/login", json={"username": "ghost", "password": "nope-nope-nope"})
    assert wrong_pw.status_code == no_user.status_code == 401
    assert wrong_pw.json == no_user.json  # same answer, so usernames can't be enumerated
    assert c.post("/logout").status_code == 200


# EN-8 SR-04 Session timeout and account lockout
def test_en8_lockout_and_timeout(app):
    c = app.test_client()
    for _ in range(5):
        assert c.post("/login", json={"username": "reporter", "password": "wrong-password!"}).status_code == 401
    assert c.post("/login", json={"username": "reporter", "password": PW}).status_code == 401  # locked out
    r = app.test_client().post("/login", json={"username": "analyst", "password": PW})
    assert "Expires=" in r.headers["Set-Cookie"]
    assert app.permanent_session_lifetime.total_seconds() == 1800


# EN-9 SR-02 Role check on every request
def test_en9_role_checked_every_request(app, login):
    assert app.test_client().get("/me").status_code == 401
    c = login("analyst")
    assert c.get("/me").json["role"] == "ANALYST"
    with app.app_context():
        get_db().execute("UPDATE users SET locked = 1 WHERE id = ?", (app.ids["analyst"],))
    assert c.get("/me").status_code == 401  # user re-read from the DB on every request


# EN-10 SR-08 Need-to-know incident visibility
def insert_incident(app, reporter, status="NEW", assignee=None):
    with app.app_context():
        return get_db().execute(
            "INSERT INTO incidents (title, description, status, reporter_id, assignee_id, created_at, updated_at) "
            "VALUES ('t', 'd', ?, ?, ?, '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')",
            (status, app.ids[reporter], app.ids[assignee] if assignee else None)).lastrowid


def test_en10_need_to_know(app, login):
    new = insert_incident(app, "reporter")
    theirs = insert_incident(app, "reporter", "ASSIGNED", "analyst2")
    assert login("reporter").get(f"/incidents/{new}").status_code == 200
    assert login("reporter2").get(f"/incidents/{new}").status_code == 404  # 404 not 403: IDs can't be probed
    assert login("analyst").get(f"/incidents/{new}").status_code == 200  # untriaged queue is shared
    assert login("analyst").get(f"/incidents/{theirs}").status_code == 404  # assigned to another analyst
    assert login("manager").get(f"/incidents/{theirs}").status_code == 200
    for name in ("admin", "auditor"):
        assert login(name).get(f"/incidents/{new}").status_code == 403


# EN-11 FR-01 Report an incident
def test_en11_report_incident(login):
    c = login("reporter")
    r = c.post("/incidents", json={"title": "Lost laptop", "description": "Left in a taxi"})
    assert r.status_code == 201
    inc = c.get(f"/incidents/{r.json['id']}").json
    assert inc["status"] == "NEW" and inc["severity"] is None
    assert c.post("/incidents", json={"title": " ", "description": "x"}).status_code == 400
    assert c.post("/incidents", json={"title": "x" * 201, "description": "x"}).status_code == 400


# EN-12 FR-02 Classify incident severity
def test_en12_classify(login, incident):
    iid = incident("NEW")
    assert login("reporter").post(f"/incidents/{iid}/classify", json={"severity": "LOW"}).status_code == 403
    assert login("analyst").post(f"/incidents/{iid}/classify", json={"severity": "SEVERE"}).status_code == 400
    assert login("analyst").post(f"/incidents/{iid}/classify", json={"severity": "CRITICAL"}).status_code == 200
    inc = login("manager").get(f"/incidents/{iid}").json
    assert inc["status"] == "TRIAGED" and inc["severity"] == "CRITICAL"


# EN-13 FR-03 Assign incident to an analyst
def test_en13_assign(app, login, incident):
    iid = incident("TRIAGED")
    body = {"assignee_id": app.ids["analyst"]}
    assert login("analyst").post(f"/incidents/{iid}/assign", json=body).status_code == 403  # managers only
    assert login("manager").post(f"/incidents/{iid}/assign", json={"assignee_id": app.ids["reporter"]}).status_code == 400
    assert login("manager").post(f"/incidents/{iid}/assign", json=body).status_code == 200
    inc = login("analyst").get(f"/incidents/{iid}").json
    assert inc["status"] == "ASSIGNED" and inc["assignee_id"] == app.ids["analyst"]
