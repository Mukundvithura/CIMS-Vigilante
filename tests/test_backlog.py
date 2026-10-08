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
