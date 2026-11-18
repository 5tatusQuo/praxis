"""Connections to Elasticsearch and Kibana.

A connection is a name (`lab`). Its URLs and keys come from the environment so
nothing secret or host-specific is ever committed:

    PRAXIS_ELASTIC_<NAME>_ES_URL
    PRAXIS_ELASTIC_<NAME>_KIBANA_URL
    PRAXIS_ELASTIC_<NAME>_CA_CERT            (optional path to a CA bundle)
    PRAXIS_ELASTIC_<NAME>_<ROLE>_API_KEY     (ROLE: LAB, READ, DEPLOY)
    PRAXIS_ELASTIC_<NAME>_<ROLE>_API_KEY_<CLIENT>   (a client's own key wins)
    PRAXIS_ELASTIC_<NAME>_ADMIN_USERNAME / _ADMIN_PASSWORD   (provisioning only)

Roles are separate identities on purpose: READ for collectors and backtests,
DEPLOY for CD only, LAB for writing test telemetry, ADMIN for onboarding.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Literal

import httpx

Role = Literal["lab", "read", "deploy", "admin"]
KIBANA_API_VERSION = "2023-10-31"


class ConnectionError(RuntimeError):
    pass


class ApiError(RuntimeError):
    def __init__(self, method: str, url: str, status: int, body: str):
        super().__init__(f"{method} {url} -> {status}: {body[:600]}")
        self.status = status
        self.body = body


def _env(connection: str, key: str, required: bool = True) -> str | None:
    name = f"PRAXIS_ELASTIC_{connection.upper().replace('-', '_')}_{key}"
    value = os.environ.get(name)
    if required and not value:
        raise ConnectionError(f"environment variable {name} is not set")
    return value or None


def _has_key(connection: str, role: str, client_id: str | None) -> bool:
    key = f"{role.upper()}_API_KEY"
    suffix = f"_{client_id.upper().replace('-', '_')}" if client_id else ""
    return bool(
        (suffix and _env(connection, key + suffix, required=False))
        or _env(connection, key, required=False)
    )


@dataclass
class ElasticConnection:
    name: str
    role: Role
    es: httpx.Client
    kibana: httpx.Client

    @classmethod
    def from_env(cls, name: str, role: Role, client_id: str | None = None) -> ElasticConnection:
        ca = _env(name, "CA_CERT", required=False)
        verify: Any = ca if ca else True
        headers: dict[str, str] = {}
        auth = None
        if role == "admin":
            auth = (_env(name, "ADMIN_USERNAME"), _env(name, "ADMIN_PASSWORD"))
        else:
            key_name = f"{role.upper()}_API_KEY"
            suffix = f"_{client_id.upper().replace('-', '_')}" if client_id else ""
            key = (suffix and _env(name, key_name + suffix, required=False)) or _env(name, key_name)
            headers["Authorization"] = f"ApiKey {key}"
        es = httpx.Client(
            base_url=_env(name, "ES_URL"), headers=headers, auth=auth, verify=verify, timeout=60
        )
        kibana = httpx.Client(
            base_url=_env(name, "KIBANA_URL"),
            headers={
                **headers,
                "kbn-xsrf": "praxis",
                "elastic-api-version": KIBANA_API_VERSION,
            },
            auth=auth,
            verify=verify,
            timeout=60,
        )
        return cls(name=name, role=role, es=es, kibana=kibana)

    def close(self) -> None:
        self.es.close()
        self.kibana.close()

    def __enter__(self) -> ElasticConnection:
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def call(client: httpx.Client, method: str, url: str, ok: tuple[int, ...] = (), **kwargs) -> Any:
    """Send a request; raise ApiError unless 2xx or listed in `ok`. Returns parsed JSON."""
    response = client.request(method, url, **kwargs)
    if not (response.is_success or response.status_code in ok):
        raise ApiError(method, url, response.status_code, response.text)
    if not response.content:
        return None
    try:
        return response.json()
    except ValueError:
        return response.text
