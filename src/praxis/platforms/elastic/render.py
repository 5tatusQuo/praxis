"""Render a detection into a Kibana Detection Engine rule for one client."""

from __future__ import annotations

from typing import Any

from praxis import attack
from praxis.content.docs import section
from praxis.content.loader import DetectionBundle
from praxis.content.models import Client
from praxis.content.tuning import Exclusion, ResolvedTuning
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


def exception_list_id(client_id: str, detection_id: str) -> str:
    return f"praxis-{client_id}-{detection_id.lower()}"


def _escape_wildcard(value: str, keep_wildcards: bool) -> str:
    """Escape for an Elasticsearch wildcard query, where a backslash escapes."""
    value = value.replace("\\", "\\\\")
    if not keep_wildcards:
        value = value.replace("*", "\\*").replace("?", "\\?")
    return value


def exception_entry(exclusion: Exclusion) -> dict[str, Any]:
    """One exclusion as a Kibana exception entry. Matching is case-sensitive."""
    entry: dict[str, Any] = {"field": exclusion.field, "operator": "included"}
    value = exclusion.value
    if exclusion.op == "equals":
        return {**entry, "type": "match", "value": value}
    if exclusion.op == "in":
        return {**entry, "type": "match_any", "value": list(value)}
    if exclusion.op == "wildcard":
        return {**entry, "type": "wildcard", "value": _escape_wildcard(value, True)}
    literal = _escape_wildcard(value, False)
    pattern = {
        "startswith": f"{literal}*",
        "endswith": f"*{literal}",
        "contains": f"*{literal}*",
    }[exclusion.op]
    return {**entry, "type": "wildcard", "value": pattern}


def exception_filter(tuning: ResolvedTuning) -> dict[str, Any] | None:
    """The query filter Kibana builds from an exception list, for lab replays.

    Kibana turns each entry into match_phrase / wildcard clauses and wraps the
    items in must_not; this mirrors it so the lab sees what production will.
    """
    if not tuning.exclude:
        return None
    clauses = []
    for exclusion in tuning.exclude:
        entry = exception_entry(exclusion)
        if entry["type"] == "match":
            clauses.append({"match_phrase": {entry["field"]: entry["value"]}})
        elif entry["type"] == "match_any":
            clauses.append(
                {
                    "bool": {
                        "should": [{"match_phrase": {entry["field"]: v}} for v in entry["value"]],
                        "minimum_should_match": 1,
                    }
                }
            )
        else:
            clauses.append({"wildcard": {entry["field"]: {"value": entry["value"]}}})
    return {"bool": {"must_not": [{"bool": {"should": clauses, "minimum_should_match": 1}}]}}


def _exception_extras(
    bundle: DetectionBundle, client: Client, tuning: ResolvedTuning
) -> dict[str, Any]:
    list_id = exception_list_id(client.id, bundle.id)
    items = []
    for number, exclusion in enumerate(tuning.exclude, start=1):
        item: dict[str, Any] = {
            "list_id": list_id,
            "item_id": f"{list_id}-{number}",
            "name": f"{bundle.id} tuning {number}: {exclusion.field} {exclusion.op}",
            "description": f"Rendered by PRAXIS from tuning for {client.id}. Do not edit here.",
            "type": "simple",
            "namespace_type": "single",
            "entries": [exception_entry(exclusion)],
        }
        if tuning.expires:
            item["expire_time"] = f"{tuning.expires.isoformat()}T23:59:59.000Z"
        items.append(item)
    return {
        "exception_list": {
            "list_id": list_id,
            "name": f"PRAXIS tuning: {bundle.id} for {client.id}",
            "description": "Rendered by PRAXIS from Git. Changes made here are overwritten.",
            "type": "detection",
            "namespace_type": "single",
        },
        "exception_items": items,
    }


def render_rule(bundle: DetectionBundle, client: Client, tuning: ResolvedTuning) -> RenderedRule:
    target = client.platforms.elastic
    if target is None:
        raise ValueError(f"client {client.id} has no elastic platform")
    impl = bundle.implementations["elastic"]
    meta = bundle.meta
    schedule = tuning.schedule or meta.schedule
    envelope: dict[str, Any] = {
        "rule_id": meta.id,
        "name": f"{meta.id} {meta.name}",
        "description": meta.intent,
        "type": impl.language,
        "language": impl.language,
        "query": impl.query,
        "index": resolve_indices(meta.log_sources["elastic"].indices, target.namespace),
        "interval": schedule.interval,
        "from": f"now-{schedule.lookback}",
        "severity": tuning.severity or meta.severity,
        "risk_score": meta.risk_score if tuning.risk_score is None else tuning.risk_score,
        "enabled": tuning.enabled,
        "max_signals": 100,
        "author": ["PRAXIS"],
        "license": meta.provenance.licence,
        "references": meta.references,
        "false_positives": meta.false_positives,
        "threat": threat_mapping(bundle),
        "note": section(bundle.readme, "SOC triage"),
        "tags": [MANAGED_TAG, f"praxis-version:{meta.version}", f"praxis-client:{client.id}"],
    }
    extras: dict[str, Any] = {}
    if tuning.exclude:
        extras = _exception_extras(bundle, client, tuning)
        # Deploy adds the list's saved-object id, which only the SIEM knows.
        envelope["exceptions_list"] = [
            {
                "list_id": extras["exception_list"]["list_id"],
                "type": "detection",
                "namespace_type": "single",
            }
        ]
    if not tuning.is_empty:
        envelope["tags"] = [*envelope["tags"], "praxis-tuned"]
    digest = content_hash(envelope, extras)
    envelope["tags"] = [*envelope["tags"], f"{HASH_TAG_PREFIX}{digest[:16]}"]
    return RenderedRule(
        detection_id=meta.id,
        client_id=client.id,
        platform="elastic",
        envelope=envelope,
        content_hash=digest,
        extras=extras,
        version=meta.version,
        tuning_digest=tuning.digest,
    )


def deployed_hash(rule: dict[str, Any]) -> str | None:
    for tag in rule.get("tags", []):
        if tag.startswith(HASH_TAG_PREFIX):
            return tag[len(HASH_TAG_PREFIX) :]
    return None
