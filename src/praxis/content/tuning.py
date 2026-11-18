"""Tuning: a closed set of reviewable overrides, layered per platform and client.

Resolution order (later wins): native implementation, platform overlay
(`overlays/platform/<siem>/<rule>.yml`), client tuning
(`clients/<id>/tuning/<rule>.yml`).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import date
from typing import Annotated, Any, Literal

from pydantic import Field, StringConstraints, model_validator

from praxis.content.models import DetectionId, Schedule, Severity, Strict

ExcludeOp = Literal["equals", "in", "startswith", "endswith", "contains", "wildcard"]


class Condition(Strict):
    """One test on one field."""

    field: Annotated[str, StringConstraints(pattern=r"^[A-Za-z_@][\w.@-]*$")] = Field(
        description="Logical (ECS) field name; the platform maps it to its own field."
    )
    op: ExcludeOp
    value: str | list[str]

    @model_validator(mode="after")
    def value_matches_op(self) -> Condition:
        if (self.op == "in") != isinstance(self.value, list):
            raise ValueError("`in` takes a list of values; every other op takes one string")
        if not self.value:
            raise ValueError("value must not be empty")
        return self


class Exclusion(Condition):
    """What suppresses an alert: this condition and every condition under `also`.

    Separate exclusions are alternatives: an alert is suppressed when any one
    of them matches. To narrow an exclusion, add conditions under `also`; do
    not add a second exclusion, which widens it.
    """

    also: list[Condition] = Field(
        default=[], description="More conditions that must all match as well."
    )

    def conditions(self) -> list[Condition]:
        return [Condition(field=self.field, op=self.op, value=self.value), *self.also]


class Tuning(Strict):
    rule: DetectionId
    reason: Annotated[str, StringConstraints(min_length=15)]
    evidence: list[str] = Field(default=[], description="Alert or ticket ids behind this tune.")
    author: str = Field(description="human:<name> or ai:<agent> (approved by <name>)")
    expires: date | None = None
    exclude: list[Exclusion] = []
    severity: Severity | None = None
    risk_score: int | None = Field(default=None, ge=0, le=100)
    schedule: Schedule | None = None
    enabled: bool = True
    examples: list[dict[str, Any]] = Field(
        default=[],
        description="Events this tune exists to silence: each must fire on the "
        "untuned rule and stay quiet once tuned. CI replays them in the lab.",
    )

    @model_validator(mode="after")
    def scope_rules(self) -> Tuning:
        if self.exclude and not self.evidence:
            raise ValueError("`exclude` must cite an alert or ticket in `evidence`")
        if self.exclude and not self.examples:
            raise ValueError("`exclude` needs at least one event in `examples` to prove it works")
        if self.examples and not self.exclude:
            raise ValueError("`examples` only make sense with `exclude`")
        if not self.enabled and self.expires is None:
            raise ValueError("`enabled: false` needs an `expires` date")
        if (self.severity is None) != (self.risk_score is None):
            raise ValueError("set `severity` and `risk_score` together")
        changes = (self.exclude, self.severity, self.schedule, not self.enabled)
        if not any(changes):
            raise ValueError("tuning file changes nothing")
        return self


@dataclass(frozen=True)
class ResolvedTuning:
    """The net effect of every tuning layer on one detection for one client."""

    exclude: tuple[Exclusion, ...] = ()
    severity: str | None = None
    risk_score: int | None = None
    schedule: Schedule | None = None
    enabled: bool = True
    expires: date | None = None
    layers: tuple[str, ...] = field(default=())  # e.g. ("platform", "client")

    @property
    def is_empty(self) -> bool:
        return not self.layers

    @property
    def digest(self) -> str | None:
        """Hash of the tuning's effect, recorded in packs.lock. None when untuned."""
        if self.is_empty:
            return None
        payload = {
            "exclude": [e.model_dump(exclude_defaults=True) for e in self.exclude],
            "severity": self.severity,
            "risk_score": self.risk_score,
            "schedule": self.schedule.model_dump() if self.schedule else None,
            "enabled": self.enabled,
            "expires": self.expires.isoformat() if self.expires else None,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()


def resolve(layers: list[tuple[str, Tuning]]) -> ResolvedTuning:
    """Merge layers in order. Exclusions add up; scalar overrides: later wins."""
    exclude: list[Exclusion] = []
    merged: dict[str, Any] = {}
    names = []
    expiries = []
    for name, tuning in layers:
        names.append(name)
        for exclusion in tuning.exclude:
            if exclusion not in exclude:
                exclude.append(exclusion)
        if tuning.severity is not None:
            merged["severity"], merged["risk_score"] = tuning.severity, tuning.risk_score
        if tuning.schedule is not None:
            merged["schedule"] = tuning.schedule
        if not tuning.enabled:
            merged["enabled"] = False
        if tuning.expires:
            expiries.append(tuning.expires)
    return ResolvedTuning(
        exclude=tuple(exclude),
        layers=tuple(names),
        expires=min(expiries) if expiries else None,
        **merged,
    )
