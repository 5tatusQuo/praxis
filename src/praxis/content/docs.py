"""Docs as code: every detection README follows one template."""

from __future__ import annotations

import re

REQUIRED_SECTIONS = [
    "Summary",
    "How it works",
    "Blind spots and known gaps",
    "SOC triage",
    "Tuning history",
]
MIN_SECTION_CHARS = 40
_PLACEHOLDER = re.compile(r"\b(TODO|TBD|FIXME|lorem ipsum)\b", re.IGNORECASE)


def split_sections(readme: str) -> tuple[str, dict[str, str]]:
    """Return the H1 title and a map of H2 heading -> body text."""
    title = ""
    sections: dict[str, str] = {}
    current: str | None = None
    for line in readme.splitlines():
        if line.startswith("# ") and not title:
            title = line[2:].strip()
        elif line.startswith("## "):
            current = line[3:].strip()
            sections[current] = ""
        elif current is not None:
            sections[current] += line + "\n"
    return title, {k: v.strip() for k, v in sections.items()}


def lint_readme(readme: str, detection_id: str) -> list[str]:
    problems: list[str] = []
    title, sections = split_sections(readme)
    if not title.startswith(detection_id):
        problems.append(f"README title must start with '{detection_id}'")
    headings = list(sections)
    if headings != REQUIRED_SECTIONS:
        problems.append(
            "README sections must be exactly, in order: " + ", ".join(REQUIRED_SECTIONS)
        )
    for name in REQUIRED_SECTIONS:
        body = sections.get(name)
        if body is None:
            continue
        # Tuning history may legitimately be short ("None yet.").
        if name != "Tuning history" and len(body) < MIN_SECTION_CHARS:
            problems.append(f"README section '{name}' is too short to be useful")
        if not body:
            problems.append(f"README section '{name}' is empty")
        if _PLACEHOLDER.search(body):
            problems.append(f"README section '{name}' still has a placeholder")
    return problems


def section(readme: str, name: str) -> str:
    return split_sections(readme)[1].get(name, "")
