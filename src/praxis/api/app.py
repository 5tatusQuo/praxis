"""FastAPI application: coverage, rule packs, audit and tuning previews for the dashboard.

Nothing here changes a SIEM or the content repo. The one POST endpoint
(tuning preview) only measures: it replays events in the lab and runs
read-only backtests.

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
from pydantic import BaseModel

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


# -- rule packs and audit ----------------------------------------------------------
@app.get("/api/packs", dependencies=secured)
def packs(conn: Conn, client_id: str | None = None) -> list[dict]:
    """Rule packs proposed by the Curator, newest first."""
    return db.list_packs(conn, client_id)


@app.get("/api/packs/{pack_id}", dependencies=secured)
def pack(pack_id: str, conn: Conn) -> dict:
    found = db.get_pack(conn, pack_id)
    if found is None:
        raise HTTPException(status_code=404, detail=f"no rule pack {pack_id}")
    return found


@app.get("/api/hunts", dependencies=secured)
def hunts(conn: Conn) -> list[dict]:
    """Threat-driven hunts, newest first."""
    return db.list_hunts(conn)


@app.get("/api/hunts/{hunt_id}", dependencies=secured)
def hunt(hunt_id: str, conn: Conn) -> dict:
    found = db.get_hunt(conn, hunt_id)
    if found is None:
        raise HTTPException(status_code=404, detail=f"no hunt {hunt_id}")
    return found


@app.get("/api/audit", dependencies=secured)
def audit(conn: Conn, client_id: str | None = None, limit: int = 200) -> list[dict]:
    """Agent prompts, tool calls and guardrail decisions, newest first."""
    return db.audit_log(conn, client_id, limit)


# -- tuning studio -------------------------------------------------------------------
def _studio_repo():
    from praxis import core

    try:
        return core.load_repo()
    except Exception as error:
        raise HTTPException(status_code=503, detail=f"content is not available: {error}") from error


def _studio_target(client_id: str, detection_id: str):
    from praxis.platforms import get_platform

    repo = _studio_repo()
    client = repo.clients.get(client_id)
    bundle = repo.detections.get(detection_id)
    if client is None or bundle is None or bundle not in repo.detections_for(client):
        raise HTTPException(status_code=404, detail=f"{client_id} does not run {detection_id}")
    name = client.platforms.enabled()[0]
    return repo, client, bundle, name, get_platform(name)


@app.get("/api/clients/{client_id}/rules/{detection_id}", dependencies=secured)
def rule_detail(client_id: str, detection_id: str) -> dict:
    """What the Tuning studio shows: the rendered rule, its tuning, and its alerts."""
    repo, client, bundle, name, platform = _studio_target(client_id, detection_id)
    tuning = repo.client_tuning.get((client_id, detection_id))
    rendered = platform.render(bundle, client, repo.tuning_for(detection_id, client, name))
    try:
        alerts = platform.alert_stats(client, detection_id)
    except Exception as error:  # the page still shows the rule if the SIEM is unreachable
        alerts = {"error": str(error)[:300]}
    return {
        "client": client_id,
        "detection": detection_id,
        "name": bundle.meta.name,
        "query": bundle.implementations[name].query,
        "language": bundle.implementations[name].language,
        "readme": bundle.readme,
        "envelope": rendered.envelope,
        "extras": rendered.extras,
        "tuning": tuning.model_dump(mode="json") if tuning else None,
        "alerts": alerts,
    }


class TuningPreview(BaseModel):
    exclude: list[dict]
    examples: list[dict] = []


@app.post("/api/clients/{client_id}/rules/{detection_id}/preview", dependencies=secured)
def tuning_preview(client_id: str, detection_id: str, body: TuningPreview) -> dict:
    """Live impact of a proposed exclusion. Measures only; writes nothing."""
    from pydantic import ValidationError

    from praxis.content.tuning import Exclusion, ResolvedTuning

    repo, client, bundle, name, platform = _studio_target(client_id, detection_id)
    try:
        proposed = tuple(Exclusion.model_validate(e) for e in body.exclude)
    except ValidationError as error:
        raise HTTPException(status_code=422, detail=error.errors(include_url=False)) from error
    current = repo.tuning_for(detection_id, client, name)
    combined = ResolvedTuning(exclude=(*current.exclude, *proposed), layers=("preview",))
    sources = bundle.meta.log_sources[name].indices
    query = bundle.implementations[name].query
    before = platform.backtest(client, query, sources, tuning=current)["hits"]
    after = platform.backtest(client, query, sources, tuning=combined)["hits"]
    positives = [
        {"name": case.name, "fires": platform.lab_fires(bundle, case.events, combined)}
        for case in bundle.positive
    ]
    examples = [
        {
            "fires_untuned": platform.lab_fires(bundle, [event], current),
            "fires_tuned": platform.lab_fires(bundle, [event], combined),
        }
        for event in body.examples
    ]
    return {
        "matches_before": before,
        "matches_after": after,
        "suppressed": before - after,
        "days": 30,
        "positives": positives,
        "positives_still_fire": all(p["fires"] for p in positives),
        "examples": examples,
        "examples_silenced": all(e["fires_untuned"] and not e["fires_tuned"] for e in examples),
    }


@app.get("/api/clients/{client_id}/rules", dependencies=secured)
def client_rules(client_id: str) -> list[dict]:
    repo = _studio_repo()
    client = repo.clients.get(client_id)
    if client is None:
        raise HTTPException(status_code=404, detail=f"unknown client {client_id}")
    return [
        {
            "id": b.id,
            "name": b.meta.name,
            "lifecycle": b.meta.lifecycle,
            "tuned": (client_id, b.id) in repo.client_tuning,
        }
        for b in repo.detections_for(client)
    ]
