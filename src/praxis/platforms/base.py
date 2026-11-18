"""The contract every SIEM platform implements."""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Literal

from praxis.content.loader import DetectionBundle
from praxis.content.models import Client
from praxis.content.tuning import ResolvedTuning
from praxis.visibility.inventory import RuleHealth, SourceInventory


@dataclass(frozen=True)
class RenderedRule:
    """A platform envelope ready to deploy, plus the hash that pins it."""

    detection_id: str
    client_id: str
    platform: str
    envelope: dict[str, Any]
    content_hash: str
    # Companion objects deployed with the rule (Elastic: its exception list).
    extras: dict[str, Any] = field(default_factory=dict)
    version: int = 1
    tuning_digest: str | None = None


def content_hash(envelope: dict[str, Any], extras: dict[str, Any] | None = None) -> str:
    payload: dict[str, Any] = {"envelope": envelope, "extras": extras} if extras else envelope
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass(frozen=True)
class CaseResult:
    """One lab replay. `expected` says whether the rule should have fired."""

    detection_id: str
    platform: str
    name: str
    scope: str  # "base" or the client id whose tuning was applied
    expected: bool
    fired: bool
    error: str | None = None

    @property
    def passed(self) -> bool:
        return self.error is None and self.fired == self.expected


@dataclass(frozen=True)
class DeployAction:
    detection_id: str
    action: Literal["created", "updated", "unchanged", "deleted"]
    content_hash: str | None = None


@dataclass(frozen=True)
class ConnectionCheck:
    role: str
    ok: bool
    detail: str


@dataclass(frozen=True)
class SmokeResult:
    detection_id: str
    ok: bool
    status: str
    detail: str = ""


class Platform(ABC):
    name: str
    # File extension -> query language, e.g. {"eql": "eql"} for elastic.eql.
    languages: dict[str, str]

    def supports(self, client: Client) -> bool:
        return getattr(client.platforms, self.name, None) is not None

    @abstractmethod
    def check(self, bundle: DetectionBundle) -> list[str]:
        """Static checks that need no SIEM: style rules and the tuning hook."""

    @abstractmethod
    def render(
        self, bundle: DetectionBundle, client: Client, tuning: ResolvedTuning
    ) -> RenderedRule:
        """Build the deployable envelope for one client, with its tuning applied."""

    @abstractmethod
    def lab_fires(
        self, bundle: DetectionBundle, events: list[dict], tuning: ResolvedTuning | None
    ) -> bool:
        """Replay events in a throwaway corner of the lab SIEM; did the rule fire?

        With `tuning`, its exclusions apply exactly as they would once deployed.
        """

    @abstractmethod
    def replay(self, bundle: DetectionBundle, client: Client, events: list[dict]) -> int:
        """Write events into a (fictional) client's telemetry. Returns the event count."""

    @abstractmethod
    def write_telemetry(self, client: Client, source: str, events: list[dict]) -> int:
        """Lab only: write events (with their own timestamps) to one of a client's sources."""

    @abstractmethod
    def last_seeded_event(self, client: Client, source: str) -> str | None:
        """Timestamp of the newest lab-generated event (labels.praxis_lab = seed), if any."""

    @abstractmethod
    def collect_sources(
        self, client: Client, fields: dict[str, list[str]]
    ) -> list[SourceInventory]:
        """Read-only telemetry inventory over the last 14 days.

        `fields` maps a catalog source to the fields whose population to measure.
        """

    @abstractmethod
    def collect_rules(self, client: Client) -> list[RuleHealth]:
        """Read-only health of every PRAXIS-managed rule in the client's SIEM."""

    @abstractmethod
    def backtest(
        self,
        client: Client,
        query: str,
        sources: list[str],
        days: int = 30,
        tuning: ResolvedTuning | None = None,
    ) -> dict[str, Any]:
        """Run a native query read-only over a client's recent data.

        Returns {"hits", "capped", "days", "samples"}; `capped` means there were at
        least that many matches. Samples are few and redacted, fit
        to show an LLM. Raises on an invalid query.
        """

    @abstractmethod
    def alert_stats(self, client: Client, detection_id: str, days: int = 30) -> dict[str, Any]:
        """Aggregated alerts for one rule: totals, top values of key fields, redacted samples."""

    @abstractmethod
    def check_connection(self, client: Client) -> list[ConnectionCheck]:
        """Connect mode: prove the read and deploy identities work for this client."""

    @abstractmethod
    def provision(self, client: Client, rotate: bool = False) -> list[str]:
        """Onboard a client (space/app, scoped identities). Returns ENV=value lines for new keys."""

    @abstractmethod
    def deprovision(self, client: Client, delete_space: bool, delete_data: bool) -> list[str]:
        """Offboard a client from its SIEM: rules and identities, optionally space and data.

        Returns what was removed. Cannot be undone.
        """

    @abstractmethod
    def live_differences(self, rule: RenderedRule, client: Client) -> list[str]:
        """Field-by-field differences between a rendered rule and what the SIEM runs."""

    @abstractmethod
    def deploy(
        self, rules: list[RenderedRule], client: Client, force: bool = False
    ) -> list[DeployAction]:
        """Make the client's SIEM match `rules`: create, update in place, delete extras."""

    @abstractmethod
    def smoke(self, rules: list[RenderedRule], client: Client) -> list[SmokeResult]:
        """After deploy: each rule exists, is enabled and its latest run succeeded."""
