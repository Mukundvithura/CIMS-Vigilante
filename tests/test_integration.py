"""Integration tests: HTTP -> service -> database -> evidence folder -> audit log (Phase 14)."""
import io
from pathlib import Path

from app.db import get_db


def test_evidence_upload_is_hashed_stored_verified_and_audited(app, login, incident):
    iid = incident("ASSIGNED")
    ana = login("analyst")
    data = b"From: attacker@example.com\nSubject: invoice\n"

    r = ana.post(f"/incidents/{iid}/evidence",
                 data={"file": (io.BytesIO(data), "../../mail.eml")},
                 content_type="multipart/form-data")
    assert r.status_code == 201
    ev_id = r.json["id"]

    # File on disk: random name, never the client's path, and the same bytes.
    stored = list(Path(app.config["EVIDENCE_DIR"]).iterdir())
    assert len(stored) == 1 and ".." not in stored[0].name
    assert stored[0].read_bytes() == data

    # Database row matches the upload.
    with app.app_context():
        row = get_db().execute("SELECT sha256, size FROM evidence WHERE id = ?", (ev_id,)).fetchone()
    assert row["size"] == len(data)
    assert ana.get(f"/evidence/{ev_id}/verify").json["intact"] is True

    # Audit trail records the upload and the verification (auditor-only view).
    auditor = login("auditor")
    recorded = {a["action"] for a in auditor.get("/audit").json}
    assert {"EVIDENCE_ADDED", "EVIDENCE_VERIFIED"} <= recorded
    assert auditor.get("/audit/verify").json["intact"] is True


def test_tampered_file_is_detected_and_logged(app, login, incident):
    iid = incident("ASSIGNED")
    ana = login("analyst")
    ev_id = ana.post(f"/incidents/{iid}/evidence",
                     data={"file": (io.BytesIO(b"original"), "a.txt")},
                     content_type="multipart/form-data").json["id"]

    stored = next(Path(app.config["EVIDENCE_DIR"]).iterdir())
    stored.write_bytes(b"swapped after upload")

    result = ana.get(f"/evidence/{ev_id}/verify").json
    assert result["intact"] is False
    assert "EVIDENCE_TAMPERED" in {a["action"] for a in login("auditor").get("/audit").json}
