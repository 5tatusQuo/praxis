"""Read the content repo from disk and report every problem found."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from pydantic import ValidationError

from praxis.content.models import Client, ContentPack, Detection


@dataclass(frozen=True)
class Issue:
    path: Path
    message: str

    def __str__(self) -> str:
        return f"{self.path}: {self.message}"


@dataclass(frozen=True)
class Implementation:
    platform: str
    language: str
    path: Path
    query: str


@dataclass(frozen=True)
class TestCase:
    name: str
    path: Path
    events: list[dict]


@dataclass
class DetectionBundle:
    """One detection folder: metadata, docs, native queries and test events."""

    path: Path
    meta: Detection
    readme: str
    implementations: dict[str, Implementation] = field(default_factory=dict)
    positive: list[TestCase] = field(default_factory=list)
    negative: list[TestCase] = field(default_factory=list)

    @property
    def id(self) -> str:
        return self.meta.id


def _format_validation(err: ValidationError) -> list[str]:
    return [f"{'.'.join(str(p) for p in e['loc']) or '(root)'}: {e['msg']}" for e in err.errors()]


def _load_yaml(path: Path, model, issues: list[Issue]):
    try:
        raw = yaml.safe_load(path.read_text())
    except yaml.YAMLError as err:
        issues.append(Issue(path, f"invalid YAML: {err}"))
        return None
    try:
        return model.model_validate(raw)
    except ValidationError as err:
        issues.extend(Issue(path, msg) for msg in _format_validation(err))
        return None


class ContentRepo:
    """The loaded content repo. `issues` lists everything that failed to load."""

    def __init__(self, root: Path, implementation_files: dict[str, tuple[str, str]]):
        """`implementation_files` maps a file name (elastic.eql) to (platform, language)."""
        self.root = root
        self.detections: dict[str, DetectionBundle] = {}
        self.packs: dict[str, ContentPack] = {}
        self.clients: dict[str, Client] = {}
        self.issues: list[Issue] = []
        self._implementation_files = implementation_files
        self._load()

    # -- loading -----------------------------------------------------------
    def _load(self) -> None:
        if not self.root.is_dir():
            self.issues.append(Issue(self.root, "content directory does not exist"))
            return
        for folder in sorted(p for p in (self.root / "detections").glob("*") if p.is_dir()):
            self._load_detection(folder)
        for path in sorted((self.root / "content-packs").glob("*.yml")):
            pack = _load_yaml(path, ContentPack, self.issues)
            if pack is None:
                continue
            if pack.id != path.stem:
                self.issues.append(Issue(path, f"pack id {pack.id!r} must match the file name"))
            self.packs[pack.id] = pack
        for path in sorted((self.root / "clients").glob("*/client.yml")):
            client = _load_yaml(path, Client, self.issues)
            if client is None:
                continue
            if client.id != path.parent.name:
                self.issues.append(Issue(path, f"client id {client.id!r} must match its folder"))
            self.clients[client.id] = client
        self._check_references()

    def _load_detection(self, folder: Path) -> None:
        meta_path = folder / "detection.yml"
        if not meta_path.is_file():
            self.issues.append(Issue(folder, "missing detection.yml"))
            return
        meta = _load_yaml(meta_path, Detection, self.issues)
        if meta is None:
            return
        if not folder.name.startswith(f"{meta.id}-"):
            self.issues.append(Issue(folder, f"folder name must start with '{meta.id}-'"))
        if meta.id in self.detections:
            self.issues.append(Issue(folder, f"duplicate detection id {meta.id}"))
            return
        readme_path = folder / "README.md"
        readme = readme_path.read_text() if readme_path.is_file() else ""
        if not readme:
            self.issues.append(Issue(folder, "missing README.md"))
        bundle = DetectionBundle(path=folder, meta=meta, readme=readme)
        for name, (platform, language) in self._implementation_files.items():
            path = folder / name
            if not path.is_file():
                continue
            if platform in bundle.implementations:
                self.issues.append(Issue(path, f"second implementation for {platform}"))
                continue
            bundle.implementations[platform] = Implementation(
                platform=platform, language=language, path=path, query=path.read_text().strip()
            )
        if not bundle.implementations:
            self.issues.append(Issue(folder, "no native implementation found"))
        for platform in bundle.implementations:
            if platform not in meta.log_sources:
                self.issues.append(
                    Issue(meta_path, f"log_sources.{platform} is required by {platform} query")
                )
        bundle.positive = self._load_tests(folder / "tests" / "positive")
        bundle.negative = self._load_tests(folder / "tests" / "negative")
        if not bundle.positive:
            self.issues.append(Issue(folder, "needs at least one tests/positive/*.json"))
        if not bundle.negative:
            self.issues.append(Issue(folder, "needs at least one tests/negative/*.json"))
        self.detections[meta.id] = bundle

    def _load_tests(self, folder: Path) -> list[TestCase]:
        cases = []
        for path in sorted(folder.glob("*.json")):
            try:
                raw = json.loads(path.read_text())
            except json.JSONDecodeError as err:
                self.issues.append(Issue(path, f"invalid JSON: {err}"))
                continue
            events = raw if isinstance(raw, list) else [raw]
            if not events or not all(isinstance(e, dict) for e in events):
                self.issues.append(Issue(path, "must be one event object or a list of them"))
                continue
            cases.append(TestCase(name=path.stem, path=path, events=events))
        return cases

    def _check_references(self) -> None:
        for pack in self.packs.values():
            for det_id in pack.detections:
                if det_id not in self.detections:
                    path = self.root / "content-packs" / f"{pack.id}.yml"
                    self.issues.append(Issue(path, f"unknown detection {det_id}"))
        for client in self.clients.values():
            path = self.root / "clients" / client.id / "client.yml"
            for pack_id in client.packs:
                if pack_id not in self.packs:
                    self.issues.append(Issue(path, f"unknown content pack {pack_id!r}"))
            for det_id in client.detections:
                if det_id not in self.detections:
                    self.issues.append(Issue(path, f"unknown detection {det_id}"))

    # -- queries -----------------------------------------------------------
    def detections_for(self, client: Client) -> list[DetectionBundle]:
        """Detections a client subscribes to (packs plus client-only), in id order."""
        ids: set[str] = set(client.detections)
        for pack_id in client.packs:
            pack = self.packs.get(pack_id)
            if pack:
                ids.update(pack.detections)
        return [self.detections[i] for i in sorted(ids) if i in self.detections]
