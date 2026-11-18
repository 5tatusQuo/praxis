"""Schemas for the files in the content repo (detection.yml, packs, clients)."""

from __future__ import annotations

import re
from datetime import date
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

DetectionId = Annotated[str, StringConstraints(pattern=r"^PRX-\d{6}$")]
Slug = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9-]{1,40}$")]
# Elastic data-stream namespaces and Kibana space ids share this safe subset.
Namespace = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{1,30}$")]
Duration = Annotated[str, StringConstraints(pattern=r"^\d+[smhd]$")]

Severity = Literal["low", "medium", "high", "critical"]
Lifecycle = Literal["draft", "staged", "production", "deprecated"]
# Pyramid of Pain, lowest (easiest for an attacker to change) to highest.
PyramidTier = Literal["hash", "ip", "domain", "artifact", "tool", "ttp"]

_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def duration_seconds(value: str) -> int:
    return int(value[:-1]) * _UNITS[value[-1]]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AttackRef(Strict):
    technique: Annotated[str, StringConstraints(pattern=r"^T\d{4}(\.\d{3})?$")]
    tactic: Annotated[str, StringConstraints(pattern=r"^TA\d{4}$")]


class Schedule(Strict):
    interval: Duration = "5m"
    lookback: Duration = "6m"

    @model_validator(mode="after")
    def lookback_covers_interval(self) -> Schedule:
        if duration_seconds(self.lookback) < duration_seconds(self.interval):
            raise ValueError("schedule.lookback must be >= schedule.interval")
        return self


class Provenance(Strict):
    source: str = Field(description="praxis, sigmahq, elastic, splunk-escu, sentinel, ...")
    upstream_id: str | None = None
    upstream_commit: str | None = None
    licence: str


ELASTIC_INDEX_RE = re.compile(r"^(logs|metrics|traces)-[a-z0-9_.]+-\*$")


class LogSource(Strict):
    """What a detection needs from one platform.

    Elastic: data-stream patterns ending in `-*`. The trailing `*` is the
    namespace, which the renderer replaces with the client's namespace.
    """

    indices: list[str] = Field(min_length=1)


class Detection(Strict):
    id: DetectionId
    name: Annotated[str, StringConstraints(min_length=5, max_length=120)]
    intent: Annotated[str, StringConstraints(min_length=20, max_length=400)] = Field(
        description="One sentence: the behaviour this detects and why it matters."
    )
    version: int = Field(ge=1)
    lifecycle: Lifecycle
    owner: str
    severity: Severity
    risk_score: int = Field(ge=0, le=100)
    attack: list[AttackRef] = Field(min_length=1)
    data_components: list[str] = Field(min_length=1)
    pyramid_tier: PyramidTier
    log_sources: dict[str, LogSource] = Field(min_length=1)
    schedule: Schedule = Schedule()
    provenance: Provenance
    references: list[str] = []
    false_positives: list[str] = []
    quality_score: float | None = Field(default=None, ge=0, le=100)
    expires: date | None = Field(
        default=None, description="Required for IOC-tier and single-campaign rules."
    )

    @model_validator(mode="after")
    def ioc_rules_expire(self) -> Detection:
        if self.pyramid_tier in ("hash", "ip", "domain") and self.expires is None:
            raise ValueError("IOC-tier detections (hash, ip, domain) must set `expires`")
        return self


class ContentPack(Strict):
    id: Slug
    name: str
    description: str
    detections: list[DetectionId]


class ElasticTarget(Strict):
    connection: Slug = Field(
        description="Name of a connection; its URLs and keys come from the environment."
    )
    space: Namespace = Field(description="Kibana space that holds this client's rules.")
    namespace: Namespace = Field(description="Data-stream namespace of this client's logs.")


class ClientPlatforms(Strict):
    elastic: ElasticTarget | None = None

    def enabled(self) -> list[str]:
        return [name for name in type(self).model_fields if getattr(self, name) is not None]


class Client(Strict):
    id: Slug
    name: str
    sector: str
    fictional: Literal[True] = Field(
        description="This repo only holds fictional clients; real ones live in praxis-content."
    )
    platforms: ClientPlatforms
    packs: list[Slug] = []
    detections: list[DetectionId] = Field(default=[], description="Client-only detections.")

    @model_validator(mode="after")
    def has_platform(self) -> Client:
        if not self.platforms.enabled():
            raise ValueError("a client needs at least one platform")
        return self
