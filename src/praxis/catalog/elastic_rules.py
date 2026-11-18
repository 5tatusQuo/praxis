"""Ingest Elastic's detection-rules repo: native EQL, used as-is as the first draft."""

from __future__ import annotations

import tomllib
from pathlib import Path

from praxis.catalog.fingerprint import eql_triples, fingerprint
from praxis.catalog.model import Candidate
from praxis.content.models import ELASTIC_INDEX_RE

# Data stream dataset -> ATT&CK data components it shows (mirrors the data map).
_COMPONENTS = {
    "endpoint.events.process": ["Process Creation", "Command Execution"],
    "windows.sysmon_operational": ["Process Creation"],
    "endpoint.events.registry": ["Windows Registry Key Modification"],
    "endpoint.events.network": ["Network Connection Creation"],
    "endpoint.events.file": ["File Creation"],
    "system.security": ["Logon Session Creation", "User Account Authentication"],
}


def _techniques(rule: dict) -> list[str]:
    found: set[str] = set()
    for threat in rule.get("threat") or []:
        for technique in threat.get("technique") or []:
            subs = [s["id"] for s in technique.get("subtechnique") or [] if "id" in s]
            found.update(subs or [technique.get("id", "")])
    return sorted(t for t in found if t)


def parse_rule(path: Path, root: Path, commit: str, licence: str, redistribute: bool):
    raw = path.read_text(errors="replace")
    try:
        document = tomllib.loads(raw)
    except tomllib.TOMLDecodeError:
        return None
    rule = document.get("rule") or {}
    metadata = document.get("metadata") or {}
    # Only EQL can be drafted for the Elastic platform today; other rule types
    # (KQL, ES|QL, machine learning, threshold) are left out until supported.
    if rule.get("type") != "eql" or not rule.get("query") or not rule.get("rule_id"):
        return None
    indices = [i for i in rule.get("index") or [] if ELASTIC_INDEX_RE.match(i)]
    components = sorted(
        {c for i in indices for c in _COMPONENTS.get(i.split("-", 1)[1].rsplit("-", 1)[0], [])}
    )
    query = rule["query"].strip()
    triples = eql_triples(query)
    tags = [str(t) for t in rule.get("tags") or []]
    candidate = Candidate(
        id=f"elastic:{rule['rule_id']}",
        source="elastic",
        upstream_id=str(rule["rule_id"]),
        path=str(path.relative_to(root)),
        commit=commit,
        licence=licence,
        redistribute=redistribute,
        title=str(rule.get("name", "")),
        description=str(rule.get("description", "")).strip(),
        status=str(metadata.get("maturity", "")),
        level=str(rule.get("severity", "")),
        author=", ".join(rule.get("author") or []),
        techniques=_techniques(rule),
        logsource={"indices": ", ".join(rule.get("index") or [])},
        log_sources={"elastic": indices} if indices else {},
        data_components=components,
        references=[str(r) for r in rule.get("references") or []],
        false_positives=[str(f).strip() for f in rule.get("false_positives") or []],
        raw=raw,
        # Already native. Still a draft: PRAXIS queries must not name indices
        # and get their own tests and docs before they ship.
        drafts={"elastic": query} if indices else {},
        triples=triples,
        fingerprint=fingerprint(triples),
    )
    return candidate, tags


def load(root: Path, paths: list[str], commit: str, licence: str, redistribute: bool):
    for folder in paths:
        for path in sorted((root / folder).rglob("*.toml")):
            parsed = parse_rule(path, root, commit, licence, redistribute)
            if parsed:
                yield parsed
