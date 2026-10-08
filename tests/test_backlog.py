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


# EN-14 FR-05 Record investigation notes
def test_en14_notes(login, incident):
    iid = incident("ASSIGNED")
    assert login("analyst").post(f"/incidents/{iid}/notes", json={"note": "IOC: 185.220.101.4"}).status_code == 201
    assert login("analyst2").post(f"/incidents/{iid}/notes", json={"note": "x"}).status_code == 404
    assert login("manager").get(f"/incidents/{iid}").json["notes"][0]["note"] == "IOC: 185.220.101.4"
    assert login("manager").post(f"/incidents/{incident('NEW')}/notes", json={"note": "x"}).status_code == 409


# EN-15 FR-06 Move incident through the status workflow
def test_en15_status_workflow(login, incident):
    iid = incident("ASSIGNED")
    ana = login("analyst")
    assert ana.post(f"/incidents/{iid}/status", json={"status": "RESOLVED"}).status_code == 409  # can't skip
    assert login("manager").post(f"/incidents/{iid}/status", json={"status": "INVESTIGATING"}).status_code == 403
    assert login("analyst2").post(f"/incidents/{iid}/status", json={"status": "INVESTIGATING"}).status_code == 404
    assert ana.post(f"/incidents/{iid}/status", json={"status": "INVESTIGATING"}).status_code == 200
    assert ana.post(f"/incidents/{iid}/status", json={"status": "RESOLVED"}).status_code == 200
    assert ana.get(f"/incidents/{iid}").json["status"] == "RESOLVED"


# EN-16 FR-07 Close an incident with a reason
def test_en16_close_with_reason(login, incident):
    iid = incident("RESOLVED")
    mgr = login("manager")
    assert login("analyst").post(f"/incidents/{iid}/status", json={"status": "CLOSED", "reason": "done"}).status_code == 403
    assert mgr.post(f"/incidents/{iid}/status", json={"status": "CLOSED"}).status_code == 400  # reason required
    assert mgr.post(f"/incidents/{iid}/status", json={"status": "CLOSED", "reason": "Contained"}).status_code == 200
    assert mgr.post(f"/incidents/{iid}/notes", json={"note": "late"}).status_code == 409  # closed is read-only


# EN-17 FR-08 View incidents and details
def test_en17_view_lists(login, incident):
    mine, other = incident("NEW"), incident("ASSIGNED")  # "other" is assigned to analyst

    def visible(name):
        return {i["id"] for i in login(name).get("/incidents").json}

    assert {mine, other} <= visible("manager")
    assert mine in visible("analyst2") and other not in visible("analyst2")
    assert {mine, other} <= visible("reporter") and not visible("reporter2")
    detail = login("manager").get(f"/incidents/{other}").json
    assert {"title", "description", "status", "severity", "notes"} <= detail.keys()


# EN-18 FR-12 Reopen a resolved incident
def test_en18_reopen(login, incident):
    iid = incident("RESOLVED")
    mgr = login("manager")
    assert login("analyst").post(f"/incidents/{iid}/status", json={"status": "INVESTIGATING"}).status_code == 403
    assert mgr.post(f"/incidents/{iid}/status", json={"status": "INVESTIGATING"}).status_code == 400  # reason required
    assert mgr.post(f"/incidents/{iid}/status", json={"status": "INVESTIGATING", "reason": "IOC seen again"}).status_code == 200
    closed = incident("CLOSED")
    assert mgr.post(f"/incidents/{closed}/status", json={"status": "INVESTIGATING", "reason": "x"}).status_code == 409


# EN-19 SR-07 Validate all input at the trust boundary
def test_en19_input_validation(app, login, incident):
    rep = login("reporter")
    assert rep.post("/incidents", data="not json", content_type="text/plain").status_code == 400
    assert rep.post("/incidents", json=["a list"]).status_code == 400
    assert rep.post("/incidents", json={"title": "bad\x00title", "description": "d"}).status_code == 400
    assert rep.post("/incidents", json={"title": 123, "description": "d"}).status_code == 400
    c = app.test_client()
    assert c.post("/login", json={"username": "a" * 33, "password": "x"}).status_code == 400
    assert c.post("/login", json={"username": ["admin"], "password": "x"}).status_code == 400
    iid = incident("TRIAGED")
    assert login("manager").post(f"/incidents/{iid}/assign", json={"assignee_id": "3"}).status_code == 400


# EN-20 FR-04 Upload evidence with SHA-256 hash
def test_en20_evidence_upload(app, login, incident):
    iid = incident("INVESTIGATING")
    data = b"malicious payload sample"
    r = upload(login("analyst"), iid, data, "../../etc/passwd")
    assert r.status_code == 201 and r.json["sha256"] == hashlib.sha256(data).hexdigest()
    ev = login("manager").get(f"/incidents/{iid}").json["evidence"][0]
    assert ev["filename"] == "etc_passwd" and ev["sha256"] == r.json["sha256"]
    stored = list(Path(app.config["EVIDENCE_DIR"]).iterdir())
    assert len(stored) == 1 and stored[0].name != ev["filename"]  # random name on disk, no path traversal
    assert upload(login("analyst"), iid, b"x" * (5 * 1024 * 1024 + 1), "big.bin").status_code == 413
    with app.app_context(), pytest.raises(sqlite3.IntegrityError):
        get_db().execute("UPDATE evidence SET sha256 = 'forged'")  # evidence rows are immutable


# EN-21 FR-09 Verify evidence still matches its hash
def test_en21_verify_evidence(app, login, incident):
    iid = incident("INVESTIGATING")
    ana = login("analyst")
    eid = upload(ana, iid, b"pcap bytes", "c2.pcap").json["id"]
    assert ana.get(f"/evidence/{eid}/verify").json["intact"] is True
    next(Path(app.config["EVIDENCE_DIR"]).iterdir()).write_bytes(b"tampered")
    r = ana.get(f"/evidence/{eid}/verify").json
    assert r["intact"] is False and r["actual_sha256"] == hashlib.sha256(b"tampered").hexdigest()
    assert login("analyst2").get(f"/evidence/{eid}/verify").status_code == 404  # same need-to-know as the incident


# EN-22 FR-11 Create users, set roles, unlock accounts
def test_en22_admin_users(app, login):
    adm = login("admin")
    new_user = {"username": "new.analyst", "password": "long-enough-pass", "role": "ANALYST"}
    r = adm.post("/admin/users", json=new_user)
    assert r.status_code == 201
    assert adm.post("/admin/users", json=new_user).status_code == 409
    assert adm.post("/admin/users", json={**new_user, "username": "weak", "password": "short"}).status_code == 400
    assert login("manager").post("/admin/users", json={**new_user, "username": "x.y"}).status_code == 403
    assert adm.post(f"/admin/users/{r.json['id']}/role", json={"role": "MANAGER"}).status_code == 200
    c = app.test_client()
    for _ in range(5):
        c.post("/login", json={"username": "reporter2", "password": "wrong-password!"})
    assert adm.post(f"/admin/users/{app.ids['reporter2']}/unlock").status_code == 200
    login("reporter2")  # can sign in again


# EN-23 SR-06 Prevent privilege escalation
def test_en23_no_privilege_escalation(app, login):
    adm, ana = login("admin"), login("analyst")
    assert adm.post(f"/admin/users/{app.ids['admin']}/role", json={"role": "AUDITOR"}).status_code == 403
    assert ana.post(f"/admin/users/{app.ids['analyst']}/role", json={"role": "ADMIN"}).status_code == 403
    assert adm.post(f"/admin/users/{app.ids['analyst']}/role", json={"role": "ROOT"}).status_code == 400
    assert adm.post(f"/admin/users/{app.ids['analyst']}/role", json={"role": "REPORTER"}).status_code == 200
    assert ana.get("/me").json["role"] == "REPORTER"  # demotion applies to the live session at once


# EN-24 SR-05 Hash-chained append-only audit log
def test_en24_audit_chain(app, incident):
    incident("RESOLVED")
    with app.app_context():
        db = get_db()
        for sql in ("UPDATE audit_log SET details = 'x'", "DELETE FROM audit_log"):
            with pytest.raises(sqlite3.IntegrityError):
                db.execute(sql)
        assert audit.verify_chain() == (True, None)
        db.execute("DROP TRIGGER audit_no_update")  # simulate someone editing the DB file directly
        db.execute("UPDATE audit_log SET details = 'forged' WHERE id = 3")
        assert audit.verify_chain() == (False, 3)


# EN-25 FR-10 View and verify the audit log
def test_en25_view_and_verify_audit(login, incident):
    incident("ASSIGNED")
    aud = login("auditor")
    actions = {r["action"] for r in aud.get("/audit").json}
    assert {"LOGIN_OK", "INCIDENT_REPORTED", "SEVERITY_SET", "INCIDENT_ASSIGNED"} <= actions
    assert aud.get("/audit/verify").json == {"intact": True, "first_bad_id": None}
    assert login("manager").get("/audit").status_code == 403


# EN-26 SR-10 Safe error responses
def test_en26_safe_errors(app):
    @app.get("/boom")
    def boom():
        raise RuntimeError("db password=hunter2")

    c = app.test_client()
    r = c.get("/boom")
    assert r.status_code == 500 and r.json == {"error": "internal error"} and b"hunter2" not in r.data
    r = c.get("/no-such-page")
    assert r.status_code == 404 and r.is_json
    assert r.headers["X-Frame-Options"] == "DENY" and r.headers["X-Content-Type-Options"] == "nosniff"
    assert "script-src 'self'" in r.headers["Content-Security-Policy"]


# EN-27 SR-09 Load secrets from environment only
def test_en27_secrets_from_env(tmp_path, monkeypatch):
    cfg = {"DATABASE": str(tmp_path / "s.db"), "EVIDENCE_DIR": str(tmp_path / "e")}
    monkeypatch.delenv("CIMS_SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError):
        create_app(cfg)  # no secret -> refuses to start
    monkeypatch.setenv("CIMS_SECRET_KEY", "short")
    with pytest.raises(RuntimeError):
        create_app(cfg)
    monkeypatch.setenv("CIMS_SECRET_KEY", "s" * 40)
    monkeypatch.setenv("CIMS_BOOTSTRAP_ADMIN_PASSWORD", "bootstrap-admin-pass")
    r = create_app(cfg).test_client().post("/login", json={"username": "admin", "password": "bootstrap-admin-pass"})
    assert r.status_code == 200 and r.json["role"] == "ADMIN"  # first admin comes from env, no default password


# EN-28 NFR-01 Lists load within 1 second at 10,000 incidents
def test_en28_list_10k_under_1s(app, login):
    ts = "2026-01-01T00:00:00+00:00"
    with app.app_context(), transaction() as db:
        db.executemany(
            "INSERT INTO incidents (title, description, status, reporter_id, created_at, updated_at) VALUES (?,?,?,?,?,?)",
            [(f"Incident {n}", "d", "NEW", app.ids["reporter"], ts, ts) for n in range(10_000)])
    mgr = login("manager")
    start = time.perf_counter()
    r = mgr.get("/incidents")
    elapsed = time.perf_counter() - start
    assert r.status_code == 200 and len(r.json) == 10_000
    assert elapsed < 1.0, f"took {elapsed:.2f}s"


# EN-29 NFR-02 Automatic restart via /health liveness probe
def test_en29_health(app):
    r = app.test_client().get("/health")
    assert r.status_code == 200 and r.json == {"status": "ok"}


# EN-30 NFR-03 Two-field incident report form
def test_en30_two_field_report_form(app):
    c = app.test_client()
    page = c.get("/")
    assert page.status_code == 200
    form = page.data.split(b'id="report-form"')[1].split(b"</form>")[0]
    assert form.count(b'name="') == 2 and b'name="title"' in form and b'name="description"' in form
    for asset in ("app.js", "vigilante.css", "logo.png", "shield.png"):
        assert c.get(f"/static/{asset}").status_code == 200


# EN-31 NFR-04 Keep business rules out of HTTP routes
def test_en31_no_business_rules_in_routes(app):
    src = (Path(app.root_path) / "routes.py").read_text()
    assert "execute(" not in src and "get_db" not in src and "TRANSITIONS" not in src
