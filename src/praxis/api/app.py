"""FastAPI application. Read-only in this phase: coverage snapshots for the dashboard.

Auth: if PRAXIS_API_TOKEN is set, every /api route except /api/health needs
`Authorization: Bearer <token>`. OIDC login replaces this in a later phase.
"""

from __future__ import annotations

import hmac
import os
from collections.abc import Iterator
from typing import Annotated

import psycopg
from fastapi import Depends, FastAPI, Header, HTTPException, Response

from praxis import __version__, db
from praxis.visibility.engine import diff_snapshots, top_gaps
from praxis.visibility.navigator import coverage_layer

app = FastAPI(title="PRAXIS API", version=__version__)


def require_token(authorization: Annotated[str | None, Header()] = None) -> None:
    expected = os.environ.get("PRAXIS_API_TOKEN")
    if not expected:
        return
    supplied = (authorization or "").removeprefix("Bearer ").strip()
    if not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="missing or wrong bearer token")


def connection() -> Iterator[psycopg.Connection]:
    with db.connect() as conn:
        yield conn


Conn = Annotated[psycopg.Connection, Depends(connection)]
secured = [Depends(require_token)]


def _snapshot(conn: psycopg.Connection, client_id: str, snapshot_id: int | None = None) -> dict:
    snapshot = (
        db.get_snapshot(conn, client_id, snapshot_id)
        if snapshot_id is not None
        else db.latest_snapshot(conn, client_id)
    )
    if snapshot is None:
        raise HTTPException(status_code=404, detail=f"no coverage snapshot for {client_id}")
    return snapshot


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.get("/api/fleet", dependencies=secured)
def fleet(conn: Conn) -> list[dict]:
    """Every client's latest coverage summary, with the previous one for trend."""
    return db.fleet(conn)


@app.get("/api/clients/{client_id}/coverage", dependencies=secured)
def coverage(client_id: str, conn: Conn, snapshot_id: int | None = None) -> dict:
    """The latest (or a given) coverage snapshot, plus its most relevant gaps."""
    snapshot = _snapshot(conn, client_id, snapshot_id)
    return {
        **snapshot,
        "top_detection_gaps": top_gaps(snapshot, "detection_gap", 25),
        "top_visibility_gaps": top_gaps(snapshot, "visibility_gap", 25),
    }


@app.get("/api/clients/{client_id}/coverage/history", dependencies=secured)
def coverage_history(client_id: str, conn: Conn, limit: int = 90) -> list[dict]:
    return db.history(conn, client_id, min(limit, 365))


@app.get("/api/clients/{client_id}/coverage/diff", dependencies=secured)
def coverage_diff(client_id: str, conn: Conn, since: int | None = None) -> dict:
    """What changed class between two snapshots (default: the previous one and the latest)."""
    new = _snapshot(conn, client_id)
    old = (
        _snapshot(conn, client_id, since)
        if since is not None
        else db.latest_snapshot(conn, client_id, offset=1)
    )
    if old is None:
        return {"from": None, "to": new["taken_at"], "changes": []}
    return {"from": old["taken_at"], "to": new["taken_at"], "changes": diff_snapshots(old, new)}


@app.get("/api/clients/{client_id}/navigator", dependencies=secured)
def navigator(client_id: str, conn: Conn, response: Response) -> dict:
    """ATT&CK Navigator layer for the latest snapshot."""
    response.headers["Content-Disposition"] = (
        f'attachment; filename="praxis-{client_id}-coverage-layer.json"'
    )
    return coverage_layer(_snapshot(conn, client_id))
