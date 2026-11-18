"""Postgres storage for coverage snapshots. Connection string: PRAXIS_DATABASE_URL."""

from __future__ import annotations

import json
import os
from importlib import resources
from typing import Any

import psycopg
from psycopg.rows import dict_row


def connect() -> psycopg.Connection:
    url = os.environ.get("PRAXIS_DATABASE_URL")
    if not url:
        raise RuntimeError("PRAXIS_DATABASE_URL is not set")
    return psycopg.connect(url, row_factory=dict_row)


def migrate(conn: psycopg.Connection) -> list[str]:
    """Apply SQL files in src/praxis/migrations in name order, once each."""
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations "
        "(name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())"
    )
    done = {row["name"] for row in conn.execute("SELECT name FROM schema_migrations")}
    applied = []
    files = sorted(
        (f for f in resources.files("praxis.migrations").iterdir() if f.name.endswith(".sql")),
        key=lambda f: f.name,
    )
    for file in files:
        if file.name in done:
            continue
        conn.execute(file.read_text())
        conn.execute("INSERT INTO schema_migrations (name) VALUES (%s)", (file.name,))
        applied.append(file.name)
    conn.commit()
    return applied


def save_snapshot(conn: psycopg.Connection, snapshot: dict, inventory: dict) -> int:
    row = conn.execute(
        "INSERT INTO coverage_snapshots (client_id, taken_at, attack_version, summary, body, "
        "inventory) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
        (
            snapshot["client"],
            snapshot["taken_at"],
            snapshot["attack_version"],
            json.dumps(snapshot["summary"]),
            json.dumps(snapshot),
            json.dumps(inventory),
        ),
    ).fetchone()
    conn.commit()
    return row["id"]


def latest_snapshot(conn: psycopg.Connection, client_id: str, offset: int = 0) -> dict | None:
    row = conn.execute(
        "SELECT id, body FROM coverage_snapshots WHERE client_id = %s "
        "ORDER BY taken_at DESC, id DESC LIMIT 1 OFFSET %s",
        (client_id, offset),
    ).fetchone()
    return {**row["body"], "id": row["id"]} if row else None


def get_snapshot(conn: psycopg.Connection, client_id: str, snapshot_id: int) -> dict | None:
    row = conn.execute(
        "SELECT id, body FROM coverage_snapshots WHERE client_id = %s AND id = %s",
        (client_id, snapshot_id),
    ).fetchone()
    return {**row["body"], "id": row["id"]} if row else None


def history(conn: psycopg.Connection, client_id: str, limit: int = 90) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT id, taken_at, attack_version, summary FROM coverage_snapshots "
        "WHERE client_id = %s ORDER BY taken_at DESC, id DESC LIMIT %s",
        (client_id, limit),
    ).fetchall()
    return [{**row, "taken_at": row["taken_at"].isoformat()} for row in rows]


def fleet(conn: psycopg.Connection) -> list[dict[str, Any]]:
    """Latest snapshot per client, with the one before it for trend."""
    rows = conn.execute(
        """
        SELECT DISTINCT ON (client_id) client_id, id, taken_at, summary,
               body->>'client_name' AS client_name, body->>'sector' AS sector,
               (SELECT p.summary FROM coverage_snapshots p
                 WHERE p.client_id = s.client_id AND (p.taken_at, p.id) < (s.taken_at, s.id)
                 ORDER BY p.taken_at DESC, p.id DESC LIMIT 1) AS previous_summary
        FROM coverage_snapshots s
        ORDER BY client_id, taken_at DESC, id DESC
        """
    ).fetchall()
    return [{**row, "taken_at": row["taken_at"].isoformat()} for row in rows]
