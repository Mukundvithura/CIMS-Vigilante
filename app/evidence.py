"""Evidence storage with SHA-256 integrity (SR-03, UC-04)."""
import hashlib
import logging
import uuid
from pathlib import Path

from flask import current_app, g
from werkzeug.utils import secure_filename

from . import audit, incidents
from .auth import ServiceError
from .db import get_db, transaction

MAX_BYTES = 5 * 1024 * 1024


def _store():
    return Path(current_app.config["EVIDENCE_DIR"])


def add(incident_id, file_storage):
    if file_storage is None:
        raise ServiceError(400, "file is required")
    data = file_storage.read(MAX_BYTES + 1)
    if not data:
        raise ServiceError(400, "file is empty")
    if len(data) > MAX_BYTES:
        raise ServiceError(413, "file exceeds 5 MB")
    filename = (secure_filename(file_storage.filename or "") or "evidence.bin")[:100]
    digest = hashlib.sha256(data).hexdigest()
    stored_name = uuid.uuid4().hex  # never use the client's filename on disk (path traversal)
    path = _store() / stored_name
    path.write_bytes(data)
    try:
        with transaction() as db:
            incidents.require_workable(db, incident_id)
            cur = db.execute(
                "INSERT INTO evidence (incident_id, filename, stored_name, sha256, size, uploaded_by, uploaded_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (incident_id, filename, stored_name, digest, len(data), g.user["id"], audit.now()),
            )
            audit.record(db, g.user["id"], "EVIDENCE_ADDED", f"incident:{incident_id}",
                         f"evidence:{cur.lastrowid} sha256={digest}")
            return cur.lastrowid, digest
    except Exception:
        path.unlink(missing_ok=True)
        raise


def verify(evidence_id):
    db = get_db()
    ev = db.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
    if ev is None:
        raise ServiceError(404, "evidence not found")
    incidents.get(ev["incident_id"])  # same need-to-know check as the incident
    path = _store() / ev["stored_name"]
    actual = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
    intact = actual == ev["sha256"]
    with transaction() as tx:
        audit.record(tx, g.user["id"], "EVIDENCE_VERIFIED" if intact else "EVIDENCE_TAMPERED", f"evidence:{evidence_id}")
    if not intact:
        audit.security_event("EVIDENCE_TAMPERED", logging.CRITICAL, evidence=evidence_id, user=g.user["username"])
    return {"evidence_id": evidence_id, "intact": intact, "expected_sha256": ev["sha256"], "actual_sha256": actual}
