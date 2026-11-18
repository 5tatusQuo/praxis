"""The gap engine: inventory in, coverage snapshot out. Pure and deterministic.

Scoring rules are documented in docs/visibility-scoring.md; keep the two in step.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from praxis import attack
from praxis.content.loader import ContentRepo
from praxis.content.models import Client
from praxis.visibility.inventory import Inventory, RuleHealth, SourceInventory

SNAPSHOT_SCHEMA = 1
WINDOW_DAYS = 14


@dataclass(frozen=True)
class Thresholds:
    stable_days: int = 12  # days with data, of the last 14, to count as stable
    host_coverage: float = 0.8  # share of expected hosts reporting
    field_population: float = 0.9  # mean population of a component's fields
    visible_score: int = 2  # a technique is visible from this component score up


CLASSES = ("covered", "detection_gap", "visibility_gap", "blind_rule")


def expected_hosts(client: Client, sources: list[SourceInventory]) -> int:
    if client.assets:
        return client.assets.endpoints
    return max((s.hosts for s in sources), default=0)


def score_components(
    repo: ContentRepo, client: Client, inventory: Inventory, thresholds: Thresholds
) -> list[dict[str, Any]]:
    """Score each ATT&CK data component 0-4; one point per factor.

    presence, volume stability, host coverage, required-field population.
    A component takes the score of its best source.
    """
    total_hosts = expected_hosts(client, inventory.sources)
    best: dict[str, dict[str, Any]] = {}
    for source in inventory.sources:
        note = repo.datamap.get((source.platform, source.source))
        if note is None:
            continue
        for component, fields in note.data_components.items():
            # A source with nothing in the last 24 hours is silent: it scores 0
            # however good its history, because nothing can be detected on it now.
            presence = source.events_24h > 0
            stable = source.days_with_data >= thresholds.stable_days
            coverage = source.hosts / total_hosts if total_hosts else 0.0
            population = (
                sum(source.field_population.get(f, 0.0) for f in fields) / len(fields)
                if fields
                else 1.0
            )
            factors = {
                "presence": presence,
                "stability": presence and stable,
                "host_coverage": presence and coverage >= thresholds.host_coverage,
                "field_population": presence and population >= thresholds.field_population,
            }
            entry = {
                "name": component,
                "score": sum(factors.values()),
                "source": source.source,
                "table": source.table,
                "silent": source.events_14d > 0 and not presence,
                "factors": factors,
                "detail": {
                    "events_14d": source.events_14d,
                    "events_24h": source.events_24h,
                    "days_with_data": source.days_with_data,
                    "hosts": source.hosts,
                    "expected_hosts": total_hosts,
                    "host_coverage": round(coverage, 3),
                    "field_population": round(population, 3),
                },
            }
            if component not in best or entry["score"] > best[component]["score"]:
                best[component] = entry
    return sorted(best.values(), key=lambda c: c["name"])


def rule_status(rule: RuleHealth, live_tables: set[str]) -> str:
    """healthy, blind (deployed but cannot see or run) or disabled."""
    if not rule.enabled:
        return "disabled"
    if rule.last_status != "succeeded":
        return "blind"
    if not any(table in live_tables for table in rule.tables):
        return "blind"
    return "healthy"


def threat_weights(repo: ContentRepo, client: Client) -> dict[str, float]:
    """Technique -> 0..1: share of the sector's known actors using it, plus boosts."""
    profile = repo.threat_profiles.get(client.sector)
    if profile is None:
        return {}
    groups = attack.bundle()["groups"]
    weights: dict[str, float] = {}
    for group_id in profile.groups:
        for technique in groups[group_id]["techniques"]:
            weights[technique] = weights.get(technique, 0.0) + 1 / len(profile.groups)
    for technique, boost in profile.techniques.items():
        weights[technique] = weights.get(technique, 0.0) + boost
    return {t: round(min(w, 1.0), 3) for t, w in weights.items()}


def build_snapshot(
    repo: ContentRepo,
    client: Client,
    inventory: Inventory,
    thresholds: Thresholds | None = None,
) -> dict[str, Any]:
    thresholds = thresholds or Thresholds()
    components = score_components(repo, client, inventory, thresholds)
    component_score = {c["name"]: c["score"] for c in components}
    live_tables = {s.table for s in inventory.sources if s.events_24h > 0}
    weights = threat_weights(repo, client)

    rules = []
    by_technique: dict[str, list[dict[str, Any]]] = {}
    for health in sorted(inventory.rules, key=lambda r: (r.detection_id, r.platform)):
        bundle = repo.detections.get(health.detection_id)
        techniques = sorted({ref.technique for ref in bundle.meta.attack}) if bundle else []
        entry = {
            "id": health.detection_id,
            "platform": health.platform,
            "status": rule_status(health, live_tables),
            "last_status": health.last_status,
            "alerts_30d": health.alerts_30d,
            "techniques": techniques,
        }
        rules.append(entry)
        for technique in techniques:
            # A rule on a sub-technique also counts for its parent.
            for target in {technique, technique.split(".")[0]}:
                by_technique.setdefault(target, []).append(entry)

    techniques_out = []
    for technique_id, technique in attack.bundle()["techniques"].items():
        visibility = max(
            (component_score.get(c, 0) for c in technique["data_components"]), default=0
        )
        mapped = by_technique.get(technique_id, [])
        if any(r["status"] == "healthy" for r in mapped):
            klass = "covered"
        elif any(r["status"] == "blind" for r in mapped):
            klass = "blind_rule"
        elif visibility >= thresholds.visible_score:
            klass = "detection_gap"
        else:
            klass = "visibility_gap"
        techniques_out.append(
            {
                "id": technique_id,
                "name": technique["name"],
                "tactics": technique["tactics"],
                "class": klass,
                "visibility": visibility,
                "weight": weights.get(technique_id, 0.0),
                "rules": sorted({r["id"] for r in mapped}),
            }
        )

    counts = {k: sum(1 for t in techniques_out if t["class"] == k) for k in CLASSES}
    total_weight = sum(t["weight"] for t in techniques_out)
    covered_weight = sum(t["weight"] for t in techniques_out if t["class"] == "covered")
    visible = sum(1 for t in techniques_out if t["visibility"] >= thresholds.visible_score)
    known = {(s.platform, s.source) for s in inventory.sources} & set(repo.datamap)
    return {
        "schema": SNAPSHOT_SCHEMA,
        "client": client.id,
        "client_name": client.name,
        "sector": client.sector,
        "taken_at": inventory.taken_at,
        "attack_version": attack.version(),
        "thresholds": thresholds.__dict__,
        "summary": {
            "techniques": len(techniques_out),
            **counts,
            "coverage_pct": round(100 * counts["covered"] / len(techniques_out), 2),
            "weighted_coverage_pct": (
                round(100 * covered_weight / total_weight, 2) if total_weight else None
            ),
            "visible_pct": round(100 * visible / len(techniques_out), 2),
            "rules": {
                status: sum(1 for r in rules if r["status"] == status)
                for status in ("healthy", "blind", "disabled")
            },
        },
        "components": components,
        "sources": [
            {**s.__dict__, "mapped": (s.platform, s.source) in known} for s in inventory.sources
        ],
        "rules": rules,
        "techniques": techniques_out,
    }


def top_gaps(snapshot: dict[str, Any], klass: str, limit: int = 15) -> list[dict[str, Any]]:
    """Gaps of one class, most threat-relevant first. Sub-techniques before parents on ties."""
    rows = [t for t in snapshot["techniques"] if t["class"] == klass]
    return sorted(rows, key=lambda t: (-t["weight"], -t["visibility"], t["id"]))[:limit]


def diff_snapshots(old: dict[str, Any], new: dict[str, Any]) -> list[dict[str, str]]:
    """Techniques whose class changed between two snapshots."""
    before = {t["id"]: t["class"] for t in old["techniques"]}
    return [
        {"id": t["id"], "name": t["name"], "from": before.get(t["id"], "new"), "to": t["class"]}
        for t in new["techniques"]
        if before.get(t["id"]) != t["class"]
    ]
