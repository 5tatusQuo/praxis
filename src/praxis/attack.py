"""ATT&CK lookups from the bundled, pinned matrix (src/praxis/data/attack.json).

Regenerate with scripts/build_attack_bundle.py.
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources


@lru_cache
def bundle() -> dict:
    return json.loads(resources.files("praxis.data").joinpath("attack.json").read_text())


def version() -> str:
    return bundle()["version"]


def tactic_name(tactic_id: str) -> str:
    return bundle()["tactics"][tactic_id]["name"]


def technique_name(technique_id: str) -> str:
    return bundle()["techniques"][technique_id]["name"]


def technique_tactics(technique_id: str) -> list[str]:
    return bundle()["techniques"][technique_id]["tactics"]


def is_technique(technique_id: str) -> bool:
    return technique_id in bundle()["techniques"]


def is_tactic(tactic_id: str) -> bool:
    return tactic_id in bundle()["tactics"]


def url(attack_id: str) -> str:
    if attack_id.startswith("TA"):
        return f"https://attack.mitre.org/tactics/{attack_id}/"
    return f"https://attack.mitre.org/techniques/{attack_id.replace('.', '/')}/"
