"""The contract every SIEM platform implements."""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Literal

from praxis.content.loader import DetectionBundle
from praxis.content.models import Client


@dataclass(frozen=True)
class RenderedRule:
    """A platform envelope ready to deploy, plus the hash that pins it."""

    detection_id: str
    client_id: str
    platform: str
    envelope: dict[str, Any]
    content_hash: str


def content_hash(envelope: dict[str, Any]) -> str:
    canonical = json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass(frozen=True)
class CaseResult:
    name: str
    kind: Literal["positive", "negative"]
    fired: bool
    error: str | None = None

    @property
    def passed(self) -> bool:
        return self.error is None and self.fired == (self.kind == "positive")


@dataclass
class LabResult:
    detection_id: str
    platform: str
    cases: list[CaseResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return bool(self.cases) and all(c.passed for c in self.cases)


@dataclass(frozen=True)
class DeployAction:
    detection_id: str
    action: Literal["created", "updated", "unchanged", "deleted"]
    content_hash: str | None = None


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
    def render(self, bundle: DetectionBundle, client: Client) -> RenderedRule:
        """Build the deployable envelope for one client."""

    @abstractmethod
    def lab_test(self, bundle: DetectionBundle) -> LabResult:
        """Replay the detection's test events in the lab SIEM and report what fired."""

    @abstractmethod
    def replay(self, bundle: DetectionBundle, client: Client, kind: str) -> int:
        """Write test events into a (fictional) client's telemetry. Returns the event count."""

    @abstractmethod
    def provision(self, client: Client, rotate: bool = False) -> list[str]:
        """Onboard a client (space/app, scoped identities). Returns ENV=value lines for new keys."""

    @abstractmethod
    def deploy(self, rules: list[RenderedRule], client: Client) -> list[DeployAction]:
        """Make the client's SIEM match `rules`: create, update in place, delete extras."""

    @abstractmethod
    def smoke(self, rules: list[RenderedRule], client: Client) -> list[SmokeResult]:
        """After deploy: each rule exists, is enabled and its latest run succeeded."""
