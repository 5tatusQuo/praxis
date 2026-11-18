"""Render a detection into a Kibana Detection Engine rule for one client."""

from __future__ import annotations

from typing import Any

from praxis import attack
from praxis.content.docs import section
from praxis.content.loader import DetectionBundle
from praxis.content.models import Client
from praxis.platforms.base import RenderedRule, content_hash

MANAGED_TAG = "PRAXIS"
HASH_TAG_PREFIX = "praxis-hash:"


def resolve_indices(patterns: list[str], namespace: str) -> list[str]:
    """`logs-endpoint.events.process-*` -> `logs-endpoint.events.process-<namespace>`."""
    return [p[:-1] + namespace for p in patterns]


def threat_mapping(bundle: DetectionBundle) -> list[dict[str, Any]]:
    by_tactic: dict[str, dict[str, Any]] = {}
    for ref in bundle.meta.attack:
        tactic = by_tactic.setdefault(
            ref.tactic,
            {
                "framework": "MITRE ATT&CK",
                "tactic": {
                    "id": ref.tactic,
                    "name": attack.tactic_name(ref.tactic),
                    "reference": attack.url(ref.tactic),
                },
                "technique": [],
            },
        )
        parent_id = ref.technique.split(".")[0]
        parent = next((t for t in tactic["technique"] if t["id"] == parent_id), None)
        if parent is None:
            parent = {
                "id": parent_id,
                "name": attack.technique_name(parent_id),
                "reference": attack.url(parent_id),
            }
            tactic["technique"].append(parent)
        if ref.technique != parent_id:
            parent.setdefault("subtechnique", []).append(
                {
                    "id": ref.technique,
                    "name": attack.technique_name(ref.technique),
                    "reference": attack.url(ref.technique),
                }
            )
    return list(by_tactic.values())


def render_rule(bundle: DetectionBundle, client: Client) -> RenderedRule:
    target = client.platforms.elastic
    if target is None:
        raise ValueError(f"client {client.id} has no elastic platform")
    impl = bundle.implementations["elastic"]
    meta = bundle.meta
    envelope: dict[str, Any] = {
        "rule_id": meta.id,
        "name": f"{meta.id} {meta.name}",
        "description": meta.intent,
        "type": impl.language,
        "language": impl.language,
        "query": impl.query,
        "index": resolve_indices(meta.log_sources["elastic"].indices, target.namespace),
        "interval": meta.schedule.interval,
        "from": f"now-{meta.schedule.lookback}",
        "severity": meta.severity,
        "risk_score": meta.risk_score,
        "enabled": True,
        "max_signals": 100,
        "author": ["PRAXIS"],
        "license": meta.provenance.licence,
        "references": meta.references,
        "false_positives": meta.false_positives,
        "threat": threat_mapping(bundle),
        "note": section(bundle.readme, "SOC triage"),
        "tags": [MANAGED_TAG, f"praxis-version:{meta.version}", f"praxis-client:{client.id}"],
    }
    digest = content_hash(envelope)
    envelope["tags"] = [*envelope["tags"], f"{HASH_TAG_PREFIX}{digest[:16]}"]
    return RenderedRule(
        detection_id=meta.id,
        client_id=client.id,
        platform="elastic",
        envelope=envelope,
        content_hash=digest,
    )


def deployed_hash(rule: dict[str, Any]) -> str | None:
    for tag in rule.get("tags", []):
        if tag.startswith(HASH_TAG_PREFIX):
            return tag[len(HASH_TAG_PREFIX) :]
    return None
