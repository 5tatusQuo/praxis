"""Ingest SigmaHQ rules. Sigma is reference material: drafts are first drafts."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from praxis.catalog.fingerprint import fingerprint, sigma_triples
from praxis.catalog.model import Candidate

# Sigma logsource (product, category) -> PRAXIS data-map source and ATT&CK data
# components. A rule whose logsource is not here is catalogued but has no
# platform mapping yet, so it cannot be drafted or deployed.
LOGSOURCES = {
    ("windows", "process_creation"): (
        ["logs-endpoint.events.process-*", "logs-windows.sysmon_operational-*"],
        ["Process Creation", "Command Execution"],
        "process",
    ),
    ("windows", "registry_set"): (
        ["logs-endpoint.events.registry-*"],
        ["Windows Registry Key Modification"],
        "registry",
    ),
    ("windows", "registry_event"): (
        ["logs-endpoint.events.registry-*"],
        ["Windows Registry Key Modification"],
        "registry",
    ),
    ("windows", "network_connection"): (
        ["logs-endpoint.events.network-*"],
        ["Network Connection Creation"],
        "network",
    ),
    ("windows", "file_event"): (["logs-endpoint.events.file-*"], ["File Creation"], "file"),
}
_TECHNIQUE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


def eql_draft(raw: str, event_category: str) -> str | None:
    """pySigma first draft, adjusted to PRAXIS style. None when conversion fails."""
    from sigma.backends.elasticsearch import EqlBackend
    from sigma.exceptions import SigmaError
    from sigma.pipelines.elasticsearch.windows import ecs_windows
    from sigma.rule import SigmaRule

    try:
        queries = EqlBackend(ecs_windows()).convert_rule(SigmaRule.from_yaml(raw))
    except (SigmaError, Exception):  # noqa: BLE001 - upstream text is untrusted; any failure = no draft
        return None
    if len(queries) != 1:
        return None
    query = queries[0].replace(".caseless", "")
    return re.sub(r"^any where", f"{event_category} where", query)


def parse_rule(path: Path, root: Path, commit: str, licence: str, redistribute: bool):
    raw = path.read_text(errors="replace")
    try:
        rule = yaml.safe_load(raw)
    except yaml.YAMLError:
        return None
    if not isinstance(rule, dict) or "detection" not in rule or "id" not in rule:
        return None
    logsource = rule.get("logsource") or {}
    key = (logsource.get("product"), logsource.get("category"))
    indices, components, category = LOGSOURCES.get(key, ([], [], None))
    triples = sigma_triples(rule["detection"]) if isinstance(rule["detection"], dict) else []
    draft = eql_draft(raw, category) if category else None
    tags = [str(t) for t in rule.get("tags") or []]
    return Candidate(
        id=f"sigma:{rule['id']}",
        source="sigmahq",
        upstream_id=str(rule["id"]),
        path=str(path.relative_to(root)),
        commit=commit,
        licence=licence,
        redistribute=redistribute,
        title=str(rule.get("title", "")),
        description=str(rule.get("description", "")).strip(),
        status=str(rule.get("status", "")),
        level=str(rule.get("level", "")),
        author=str(rule.get("author", "")),
        techniques=sorted({m.group(1).upper() for t in tags if (m := _TECHNIQUE.match(t))}),
        logsource={k: str(v) for k, v in logsource.items()},
        log_sources={"elastic": indices} if indices else {},
        data_components=components,
        references=[str(r) for r in rule.get("references") or []],
        false_positives=[
            str(f) for f in rule.get("falsepositives") or [] if str(f).lower() != "unknown"
        ],
        raw=raw,
        drafts={"elastic": draft} if draft else {},
        triples=triples,
        fingerprint=fingerprint(triples),
    ), tags


def load(root: Path, paths: list[str], commit: str, licence: str, redistribute: bool):
    """Yield (Candidate, tags) for every parseable rule under the given folders."""
    for folder in paths:
        for path in sorted((root / folder).rglob("*.yml")):
            parsed = parse_rule(path, root, commit, licence, redistribute)
            if parsed:
                yield parsed
