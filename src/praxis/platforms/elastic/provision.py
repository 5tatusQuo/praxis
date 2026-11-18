"""Onboard a client on Elastic: a Kibana space and three scoped API keys.

Runs with the ADMIN identity. It never prints or stores the admin password.
"""

from __future__ import annotations

from typing import Any

from praxis.content.models import Client
from praxis.platforms.elastic.connection import ElasticConnection, call

KIBANA_APP = "kibana-.kibana"
# Kibana feature privileges for detection rules (Elastic 9.5 names).
RULE_FEATURES = ("siemV5", "securitySolutionRulesV4", "securitySolutionAlertsV1")


def _env_name(connection: str, role: str, client_id: str | None = None) -> str:
    name = f"PRAXIS_ELASTIC_{connection.upper().replace('-', '_')}_{role.upper()}_API_KEY"
    return f"{name}_{client_id.upper().replace('-', '_')}" if client_id else name


def _kibana_privileges(space: str, level: str) -> list[dict[str, Any]]:
    return [
        {
            "application": KIBANA_APP,
            "privileges": [f"feature_{feature}.{level}" for feature in RULE_FEATURES],
            "resources": [f"space:{space}"],
        }
    ]


def _role_descriptors(client: Client) -> dict[str, dict[str, Any]]:
    target = client.platforms.elastic
    telemetry = [f"{kind}-*-{target.namespace}" for kind in ("logs", "metrics", "traces")]
    alerts = [
        f".alerts-security.alerts-{target.space}",
        f".internal.alerts-security.alerts-{target.space}-*",
    ]
    return {
        # CD only: manage rules in the client's space. Rules run with this
        # key's privileges, so it can read the client's telemetry and nothing else.
        "deploy": {
            "cluster": [],
            "indices": [
                {"names": telemetry, "privileges": ["read", "view_index_metadata"]},
                {
                    "names": [*alerts, ".lists-*", ".items-*"],
                    "privileges": ["read", "write", "maintenance", "view_index_metadata"],
                },
            ],
            "applications": _kibana_privileges(target.space, "all"),
        },
        # Collectors and backtests: read-only everywhere.
        "read": {
            "cluster": ["monitor"],
            "indices": [
                {
                    "names": [*telemetry, *alerts],
                    "privileges": ["read", "view_index_metadata", "monitor"],
                }
            ],
            "applications": _kibana_privileges(target.space, "read"),
        },
    }


LAB_ROLE = {
    # Lab only: write and delete test telemetry in any data-stream namespace.
    "cluster": [],
    "indices": [
        {
            "names": ["logs-*-*", "metrics-*-*", "traces-*-*"],
            "privileges": [
                "auto_configure",
                "create_doc",
                "read",
                "view_index_metadata",
                "delete_index",
            ],
        }
    ],
}


def _active_keys(conn: ElasticConnection, name: str) -> list[dict[str, Any]]:
    result = call(
        conn.es, "GET", "/_security/api_key", params={"name": name, "active_only": "true"}
    )
    return result["api_keys"]


def _ensure_key(
    conn: ElasticConnection, name: str, role: dict[str, Any], rotate: bool
) -> str | None:
    """Create the key. If one is already active, keep it unless `rotate` is set."""
    existing = _active_keys(conn, name)
    if existing and not rotate:
        return None
    if existing:
        call(conn.es, "DELETE", "/_security/api_key", json={"ids": [k["id"] for k in existing]})
    created = call(
        conn.es,
        "POST",
        "/_security/api_key",
        json={"name": name, "role_descriptors": {name: role}, "metadata": {"managed_by": "praxis"}},
    )
    return created["encoded"]


def provision(client: Client, rotate: bool = False) -> list[str]:
    """Returns `ENV_NAME=value` lines for every key that was created."""
    target = client.platforms.elastic
    lines: list[str] = []
    with ElasticConnection.from_env(target.connection, "admin") as conn:
        space = call(conn.kibana, "GET", f"/api/spaces/space/{target.space}", ok=(404,))
        if not space or space.get("statusCode") == 404:
            call(
                conn.kibana,
                "POST",
                "/api/spaces/space",
                json={
                    "id": target.space,
                    "name": client.name,
                    "description": f"PRAXIS client {client.id}",
                },
            )
        lab_key = _ensure_key(conn, "praxis-lab", LAB_ROLE, rotate)
        if lab_key:
            lines.append(f"{_env_name(target.connection, 'lab')}={lab_key}")
        for role, descriptor in _role_descriptors(client).items():
            key = _ensure_key(conn, f"praxis-{role}-{client.id}", descriptor, rotate)
            if key:
                lines.append(f"{_env_name(target.connection, role, client.id)}={key}")
    return lines
