from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml

from praxis import core
from praxis.settings import get_settings

DETECTION = {
    "id": "PRX-000900",
    "name": "Test detection for unit tests",
    "intent": "Detects a made-up behaviour so the unit tests have something to load.",
    "version": 1,
    "lifecycle": "production",
    "owner": "tests",
    "severity": "medium",
    "risk_score": 47,
    "attack": [{"technique": "T1059.001", "tactic": "TA0002"}],
    "data_components": ["Process Creation"],
    "pyramid_tier": "ttp",
    "log_sources": {"elastic": {"indices": ["logs-endpoint.events.process-*"]}},
    "provenance": {"source": "praxis", "licence": "Apache-2.0"},
}

README = """# PRX-000900 Test detection

## Summary

A made-up detection that exists only so the unit tests can load something.

## How it works

It matches a process named evil.exe starting on any host, which never happens.

## Blind spots and known gaps

Everything: it is a fixture and detects nothing real at all, by design.

## SOC triage

1. Nothing to triage, this rule only exists inside the unit tests.

## Tuning history

None yet.
"""

CLIENT = {
    "id": "testco",
    "name": "TestCo (fictional)",
    "sector": "retail",
    "fictional": True,
    "platforms": {"elastic": {"connection": "lab", "space": "testco", "namespace": "testco"}},
    "packs": ["baseline"],
}

EVENT = {"event": {"category": ["process"], "type": ["start"]}, "process": {"name": "evil.exe"}}


def write_yaml(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False))


@pytest.fixture
def content(tmp_path: Path) -> Path:
    """A minimal, valid content repo in a temp folder."""
    root = tmp_path / "content"
    det = root / "detections" / "PRX-000900-test-detection"
    write_yaml(det / "detection.yml", DETECTION)
    (det / "README.md").write_text(README)
    (det / "elastic.eql").write_text('process where process.name == "evil.exe"\n')
    for kind, event in (("positive", EVENT), ("negative", {**EVENT, "process": {"name": "ok"}})):
        folder = det / "tests" / kind
        folder.mkdir(parents=True)
        (folder / "case.json").write_text(json.dumps(event))
    write_yaml(
        root / "content-packs" / "baseline.yml",
        {"id": "baseline", "name": "Baseline", "description": "x", "detections": ["PRX-000900"]},
    )
    write_yaml(root / "clients" / "testco" / "client.yml", CLIENT)
    return root


@pytest.fixture
def repo(content: Path):
    return core.load_repo(content)


@pytest.fixture
def shipped_content(tmp_path: Path) -> Path:
    """A copy of the real content folder, located through the setting."""
    target = tmp_path / "shipped"
    shutil.copytree(get_settings().content_dir, target)
    return target
