"""What a collector reports back from a client's SIEM. Read-only facts."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class SourceInventory:
    """One table / data stream as seen over the last 14 days."""

    platform: str
    source: str  # catalog key, e.g. logs-endpoint.events.process
    table: str  # the client's own name for it, e.g. logs-endpoint.events.process-acme
    events_14d: int
    events_24h: int
    days_with_data: int  # of the last 14 full or partial days
    hosts: int  # distinct hosts reporting in 14 days
    last_event: str | None
    field_population: dict[str, float] = field(default_factory=dict)  # field -> 0..1


@dataclass
class RuleHealth:
    """A deployed PRAXIS rule as the SIEM reports it."""

    detection_id: str
    platform: str
    enabled: bool
    last_status: str | None  # succeeded, partial failure, failed, or None if never ran
    last_run: str | None
    alerts_30d: int
    deployed_hash: str | None
    tables: list[str] = field(default_factory=list)  # the rule's data sources


@dataclass
class Inventory:
    client: str
    taken_at: str
    sources: list[SourceInventory]
    rules: list[RuleHealth]

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> Inventory:
        return cls(
            client=data["client"],
            taken_at=data["taken_at"],
            sources=[SourceInventory(**s) for s in data["sources"]],
            rules=[RuleHealth(**r) for r in data["rules"]],
        )
