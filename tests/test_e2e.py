"""System (end-to-end) test: one full incident lifecycle through the HTTP API (Phase 14)."""


def test_full_incident_lifecycle_report_to_close(app, login):
    rep, mgr, ana, aud = login("reporter"), login("manager"), login("analyst"), login("auditor")

    # 1. Report
    iid = rep.post("/incidents", json={"title": "Lost laptop", "description": "Left on a train"}).json["id"]
    assert rep.get(f"/incidents/{iid}").json["status"] == "NEW"

    # 2. Classify and assign
    assert mgr.post(f"/incidents/{iid}/classify", json={"severity": "MEDIUM"}).status_code == 200
    assert mgr.post(f"/incidents/{iid}/assign", json={"assignee_id": app.ids["analyst"]}).status_code == 200

    # 3. Investigate: note, then move on
    assert ana.post(f"/incidents/{iid}/status", json={"status": "INVESTIGATING"}).status_code == 200
    assert ana.post(f"/incidents/{iid}/notes", json={"note": "Remote wipe requested"}).status_code == 201

    # 4. Resolve, then the manager reopens it (FR-12)
    assert ana.post(f"/incidents/{iid}/status", json={"status": "RESOLVED"}).status_code == 200
    assert mgr.post(f"/incidents/{iid}/status", json={"status": "INVESTIGATING", "reason": "new info"}).status_code == 200
    assert ana.post(f"/incidents/{iid}/status", json={"status": "RESOLVED"}).status_code == 200

    # 5. Close with a reason, after which the case is read only
    assert mgr.post(f"/incidents/{iid}/status", json={"status": "CLOSED", "reason": "device wiped"}).status_code == 200
    assert mgr.get(f"/incidents/{iid}").json["status"] == "CLOSED"
    assert ana.post(f"/incidents/{iid}/notes", json={"note": "late"}).status_code == 409

    # 6. The auditor sees every step and the chain is intact
    actions = [a["action"] for a in aud.get("/audit").json]
    for expected in ("INCIDENT_REPORTED", "SEVERITY_SET", "INCIDENT_ASSIGNED", "NOTE_ADDED", "STATUS_CHANGED"):
        assert expected in actions
    assert aud.get("/audit/verify").json == {"intact": True, "first_bad_id": None}
