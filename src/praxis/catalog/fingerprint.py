"""Logic fingerprints: find the same idea written twice.

A rule is reduced to a set of (field, operator, value) triples with fields
mapped to ECS and values lower-cased. Two rules are near-duplicates when the
Jaccard similarity of their (field, value) sets is high. This is approximate
by design: it ignores boolean structure, so it finds candidates for a human or
an agent to compare, it does not prove equivalence.
"""

from __future__ import annotations

import hashlib
import re

# Sigma field names (Windows) to ECS, enough for comparison across sources.
SIGMA_TO_ECS = {
    "image": "process.executable",
    "originalfilename": "process.pe.original_file_name",
    "commandline": "process.command_line",
    "parentimage": "process.parent.executable",
    "parentcommandline": "process.parent.command_line",
    "user": "user.name",
    "targetobject": "registry.path",
    "details": "registry.data.strings",
    "targetfilename": "file.path",
    "destinationip": "destination.ip",
    "destinationport": "destination.port",
    "destinationhostname": "destination.domain",
    "hashes": "process.hash",
    "imphash": "process.pe.imphash",
    "md5": "process.hash.md5",
    "sha256": "process.hash.sha256",
    "currentdirectory": "process.working_directory",
    "integritylevel": "process.integrity_level",
}
# Fields that are the same thing for comparison purposes.
_ALIASES = {
    "process.name": "process.executable",
    "process.parent.name": "process.parent.executable",
}
_EQL_COMPARISON = re.compile(
    r"\??([A-Za-z_][\w.]*)\s*(==|!=|:|like~?|regex~?|in~?)\s*(\((?:[^()]|\([^()]*\))*\)|\"(?:[^\"\\]|\\.)*\")"
)
_EQL_STRING = re.compile(r"\"((?:[^\"\\]|\\.)*)\"")


def normalise_field(name: str) -> str:
    name = name.strip().removesuffix(".caseless")
    ecs = SIGMA_TO_ECS.get(name.lower(), name).lower()
    return _ALIASES.get(ecs, ecs)


def normalise_value(value: object) -> str:
    text = str(value).lower().replace("\\\\", "\\").strip("*")
    return text.rsplit("\\", 1)[-1] if text.endswith(".exe") else text


def sigma_triples(detection: dict) -> list[list[str]]:
    """Flatten a Sigma `detection` block. Filters (`filter*` keys) are skipped."""
    triples: set[tuple[str, str, str]] = set()

    def walk(node: object) -> None:
        if isinstance(node, list):
            for item in node:
                walk(item)
        elif isinstance(node, dict):
            for key, value in node.items():
                name, *modifiers = str(key).split("|")
                operator = "|".join(m for m in modifiers if m != "all") or "equals"
                for single in value if isinstance(value, list) else [value]:
                    if single is not None and not isinstance(single, dict):
                        triples.add((normalise_field(name), operator, normalise_value(single)))

    for name, block in detection.items():
        if name in ("condition", "timeframe") or name.startswith("filter"):
            continue
        walk(block)
    return sorted([list(t) for t in triples])


def eql_triples(query: str) -> list[list[str]]:
    triples: set[tuple[str, str, str]] = set()
    for name, operator, values in _EQL_COMPARISON.findall(query):
        for value in _EQL_STRING.findall(values):
            # "*comsvcs*MiniDump*" carries two ideas; compare them one by one.
            for part in filter(None, value.split("*")):
                triples.add((normalise_field(name), operator, normalise_value(part)))
    return sorted([list(t) for t in triples])


def fingerprint(triples: list[list[str]]) -> str:
    pairs = sorted({f"{t[0]}={t[2]}" for t in triples})
    return hashlib.sha256("\n".join(pairs).encode()).hexdigest()[:16]


def similarity(a: list[list[str]], b: list[list[str]]) -> float:
    """Jaccard similarity of two rules' (field, value) sets, 0 to 1."""
    left = {(t[0], t[2]) for t in a}
    right = {(t[0], t[2]) for t in b}
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)
