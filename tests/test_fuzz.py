"""Fuzz test on input boundaries (Phase 14).

Random and boundary values are sent to the endpoints that take user input.
Pass rule: no request may return HTTP 500, and no stored text may exceed its length limit.
The seed is fixed, so every run sends the same inputs.
"""
import random

from app.db import get_db

SEEDS = ["", " ", "A", "x" * 201, "x" * 5000, "\x00", "\x1b[31m", "' OR 1=1 --",
         "<script>alert(1)</script>", "../../etc/passwd", "emoji 😀" * 20, "‮", "%s%n", "null", "-1"]
VALUES = SEEDS + [None, 0, -1, 2**63, 3.14, True, [], ["HIGH"], {}, {"$ne": None}, "HIGH", "CLOSED"]


def _mutate(rng):
    v = rng.choice(VALUES)
    if isinstance(v, str) and v and rng.random() < 0.4:
        v = v * rng.randint(1, 4) + rng.choice(SEEDS)
    return v


def test_fuzz_inputs_never_cause_a_server_error(app, login, incident):
    rng = random.Random(1337)
    mgr = login("manager")
    rep = login("reporter")
    anon = app.test_client()
    iid = incident("INVESTIGATING")
    failures = []
    counts = {}

    targets = [
        ("/incidents", lambda: {"title": _mutate(rng), "description": _mutate(rng)}, rep),
        (f"/incidents/{iid}/classify", lambda: {"severity": _mutate(rng)}, mgr),
        (f"/incidents/{iid}/status", lambda: {"status": _mutate(rng), "reason": _mutate(rng)}, mgr),
        (f"/incidents/{iid}/assign", lambda: {"assignee_id": _mutate(rng)}, mgr),
        ("/login", lambda: {"username": _mutate(rng), "password": _mutate(rng)}, anon),
    ]

    for _ in range(400):
        url, make, client = rng.choice(targets)
        body = make()
        endpoint = url.split("/")[-1]
        try:
            status = client.post(url, json=body).status_code
        except Exception as exc:  # an exception that escapes the app counts as a failure
            status = f"EXC {type(exc).__name__}"
        counts[(endpoint, str(status))] = counts.get((endpoint, str(status)), 0) + 1
        if isinstance(status, str) or status >= 500:
            failures.append((url, repr(body)[:120], status))

    # Observations are printed so they can be recorded in the report.
    for (endpoint, status), n in sorted(counts.items()):
        print(f"  {endpoint:<10} {status}: {n}")
    for url, body, status in failures[:5]:
        print(f"  FAILURE {url} {body} -> {status}")

    assert not failures, f"{len(failures)} requests failed; first: {failures[0]}"

    with app.app_context():
        longest = get_db().execute("SELECT MAX(LENGTH(title)) FROM incidents").fetchone()[0]
    assert longest <= 200
