"""Fetch pinned upstream sources and rebuild the catalog."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Annotated

import yaml
from pydantic import Field, StringConstraints

from praxis import attack
from praxis.catalog import quality, sigma
from praxis.catalog.fingerprint import eql_triples
from praxis.catalog.model import Candidate
from praxis.content.loader import ContentRepo
from praxis.content.models import Strict


class Source(Strict):
    name: str
    kind: str = Field(description="Parser to use. Supported: sigma")
    repo: str
    commit: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")] = Field(
        description="Pinned upstream commit; bump it deliberately, in a pull request."
    )
    licence: str
    redistribute: bool = Field(
        description="May rule text be copied into the content repo (with attribution)?"
    )
    paths: list[str]


class Sources(Strict):
    sources: list[Source]


def load_sources(repo: ContentRepo) -> list[Source]:
    path = repo.root / "sources.yml"
    return (
        Sources.model_validate(yaml.safe_load(path.read_text())).sources if path.is_file() else []
    )


def _git(args: list[str], cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def fetch(source: Source, cache: Path) -> Path:
    """Check out exactly the pinned commit (shallow, only the wanted folders)."""
    target = cache / source.name / source.commit
    if (target / ".praxis-complete").is_file():
        return target
    target.mkdir(parents=True, exist_ok=True)
    _git(["init", "-q"], target)
    _git(["remote", "add", "origin", source.repo], target)
    _git(["sparse-checkout", "set", *source.paths], target)
    _git(["fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", source.commit], target)
    _git(["checkout", "-q", "FETCH_HEAD"], target)
    (target / ".praxis-complete").touch()
    return target


def library_triples(repo: ContentRepo) -> dict[str, list[list[str]]]:
    """Logic of the detections already in the library, for overlap checks."""
    return {
        bundle.id: eql_triples(bundle.implementations["elastic"].query)
        for bundle in repo.detections.values()
        if "elastic" in bundle.implementations
    }


def technique_counts(repo: ContentRepo) -> dict[str, int]:
    counts: dict[str, int] = {}
    for bundle in repo.detections.values():
        for ref in bundle.meta.attack:
            counts[ref.technique] = counts.get(ref.technique, 0) + 1
    return counts


def build(repo: ContentRepo, cache: Path) -> list[Candidate]:
    """Every candidate from every pinned source, scored against the current library."""
    library = library_triples(repo)
    crowded = technique_counts(repo)
    candidates = []
    for source in load_sources(repo):
        if source.kind != "sigma":
            raise ValueError(f"unknown source kind {source.kind!r}")
        root = fetch(source, cache)
        loaded = sigma.load(root, source.paths, source.commit, source.licence, source.redistribute)
        for candidate, tags in loaded:
            candidate.techniques = [t for t in candidate.techniques if attack.is_technique(t)]
            candidate.quality = quality.profile(
                candidate.triples,
                status=candidate.status,
                title=candidate.title,
                tags=tags,
                has_false_positive_notes=bool(candidate.false_positives),
                references=len(candidate.references),
                library=library,
                same_technique_in_library=max(
                    (crowded.get(t, 0) for t in candidate.techniques), default=0
                ),
            )
            candidates.append(candidate)
    return candidates
