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


# -- candidate catalog ---------------------------------------------------------
def replace_catalog(conn: psycopg.Connection, candidates: list[dict]) -> int:
    """Swap the whole catalog in one transaction."""
    with conn.transaction():
        conn.execute("TRUNCATE catalog_candidates")
        with conn.cursor() as cursor:
            cursor.executemany(
                "INSERT INTO catalog_candidates (id, source, title, description, status, "
                "techniques, platforms, score, tier, fingerprint, body) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                [
                    (
                        c["id"],
                        c["source"],
                        c["title"],
                        c["description"],
                        c["status"],
                        c["techniques"],
                        sorted(c["drafts"]),
                        c["quality"]["score"],
                        c["quality"]["tier"],
                        c["fingerprint"],
                        json.dumps(c),
                    )
                    for c in candidates
                ],
            )
    return len(candidates)


def search_catalog(
    conn: psycopg.Connection,
    *,
    technique: str | None = None,
    text: str | None = None,
    platform: str | None = None,
    min_score: int = 0,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Candidates by technique (sub-techniques included) and/or meaning, best score first."""
    where, params = ["score >= %s"], [min_score]
    if technique:
        where.append("EXISTS (SELECT 1 FROM unnest(techniques) t WHERE t = %s OR t LIKE %s)")
        params += [technique, technique + ".%"]
    if platform:
        where.append("%s = ANY(platforms)")
        params.append(platform)
    rank = "0"
    if text:
        where.append("search @@ websearch_to_tsquery('english', %s)")
        params.append(text)
        rank = "ts_rank(search, websearch_to_tsquery('english', %s))"
    sql = (
        f"SELECT id, source, title, status, techniques, platforms, score, tier, fingerprint, "
        f"body->'quality'->'flags' AS flags, left(description, 300) AS description, "
        f"{rank} AS rank FROM catalog_candidates WHERE {' AND '.join(where)} "
        f"ORDER BY rank DESC, score DESC, id LIMIT %s"
    )
    ordered = ([text] if text else []) + params + [min(limit, 50)]
    return conn.execute(sql, ordered).fetchall()


def get_candidate(conn: psycopg.Connection, candidate_id: str) -> dict | None:
    row = conn.execute(
        "SELECT body FROM catalog_candidates WHERE id = %s", (candidate_id,)
    ).fetchone()
    return row["body"] if row else None


def catalog_stats(conn: psycopg.Connection) -> dict[str, Any]:
    return conn.execute(
        "SELECT count(*) AS candidates, count(*) FILTER (WHERE cardinality(platforms) > 0) AS "
        "drafted, count(*) FILTER (WHERE score >= 60) AS passing, "
        "count(DISTINCT fingerprint) AS distinct_logic FROM catalog_candidates"
    ).fetchone()


# -- rule packs and audit --------------------------------------------------------
def save_pack(conn: psycopg.Connection, pack: dict, pr_url: str | None) -> None:
    conn.execute(
        "INSERT INTO pack_proposals (id, client_id, month, status, pr_url, body) "
        "VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (id) DO UPDATE SET "
        "status = EXCLUDED.status, pr_url = EXCLUDED.pr_url, body = EXCLUDED.body",
        (pack["id"], pack["client"], pack["month"], pack["status"], pr_url, json.dumps(pack)),
    )
    conn.commit()


def list_packs(conn: psycopg.Connection, client_id: str | None = None) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT id, client_id, month, status, pr_url, created_at, "
        "jsonb_array_length(body->'picks') AS picks, body->'review'->>'verdict' AS verdict "
        "FROM pack_proposals WHERE (%s::text IS NULL OR client_id = %s) ORDER BY created_at DESC",
        (client_id, client_id),
    ).fetchall()
    return [{**row, "created_at": row["created_at"].isoformat()} for row in rows]


def get_pack(conn: psycopg.Connection, pack_id: str) -> dict | None:
    row = conn.execute(
        "SELECT body, pr_url, status FROM pack_proposals WHERE id = %s", (pack_id,)
    ).fetchone()
    return {**row["body"], "pr_url": row["pr_url"], "status": row["status"]} if row else None


def save_audit(conn: psycopg.Connection, events: list[dict]) -> int:
    with conn.cursor() as cursor:
        cursor.executemany(
            "INSERT INTO audit_log (at, actor, client_id, action, detail) "
            "VALUES (%s, %s, %s, %s, %s)",
            [
                (e["at"], e["actor"], e.get("client"), e["action"], json.dumps(e["detail"]))
                for e in events
            ],
        )
    conn.commit()
    return len(events)


def audit_log(
    conn: psycopg.Connection, client_id: str | None = None, limit: int = 200
) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT id, at, actor, client_id, action, detail FROM audit_log "
        "WHERE (%s::text IS NULL OR client_id = %s) ORDER BY id DESC LIMIT %s",
        (client_id, client_id, min(limit, 1000)),
    ).fetchall()
    return [{**row, "at": row["at"].isoformat()} for row in rows]
