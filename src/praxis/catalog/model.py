from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class Candidate:
    """One upstream rule in PRAXIS terms."""

    id: str  # "<source>:<upstream id>"
    source: str
    upstream_id: str
    path: str
    commit: str
    licence: str
    redistribute: bool  # may its text be copied into the content repo?
    title: str
    description: str
    status: str  # upstream maturity: stable, test, experimental, ...
    level: str  # upstream severity
    author: str
    techniques: list[str]
    logsource: dict
    # PRAXIS catalog source this maps to per platform, e.g. {"elastic": [...indices]}
    log_sources: dict[str, list[str]]
    data_components: list[str]
    references: list[str]
    false_positives: list[str]
    raw: str  # the upstream rule text, untrusted
    # First-draft native queries by platform, from pySigma. Drafts, never deployed as-is.
    drafts: dict[str, str] = field(default_factory=dict)
    triples: list[list[str]] = field(default_factory=list)  # [field, operator, value]
    fingerprint: str = ""
    quality: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)
