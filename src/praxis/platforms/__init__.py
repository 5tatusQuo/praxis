"""SIEM platforms. Everything SIEM-specific lives behind `Platform`.

Build rule: nothing outside this package may assume a particular SIEM.
"""

from __future__ import annotations

from praxis.platforms.base import (
    CaseResult,
    DeployAction,
    LabResult,
    Platform,
    RenderedRule,
    SmokeResult,
)
from praxis.platforms.elastic import ElasticPlatform

_REGISTRY: dict[str, Platform] = {p.name: p for p in (ElasticPlatform(),)}


def get_platform(name: str) -> Platform:
    try:
        return _REGISTRY[name]
    except KeyError:
        raise KeyError(f"unknown platform {name!r}; known: {sorted(_REGISTRY)}") from None


def all_platforms() -> list[Platform]:
    return list(_REGISTRY.values())


def implementation_files() -> dict[str, tuple[str, str]]:
    """File name -> (platform, language), e.g. 'elastic.eql' -> ('elastic', 'eql')."""
    return {
        f"{p.name}.{ext}": (p.name, language)
        for p in _REGISTRY.values()
        for ext, language in p.languages.items()
    }


__all__ = [
    "CaseResult",
    "DeployAction",
    "LabResult",
    "Platform",
    "RenderedRule",
    "SmokeResult",
    "all_platforms",
    "get_platform",
    "implementation_files",
]
